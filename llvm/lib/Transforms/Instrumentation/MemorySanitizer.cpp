//===-- MemorySanitizer.cpp - detector of uninitialized reads -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer, a detector uninitialized reads.
//
// Status: early prototype.
//
// The algorithm of the tool is similar to Memcheck (http://goo.gl/QKbem).
// We associate a few shadow bits with every byte of the application memory,
// poison the shadow of the malloc-ed or alloca-ed memory,
// load the shadow bits on every memory read,
// propagate the shadow bits through some of the arithmetic instruction
// (including MOV), store the shadow bits on every memory write,
// report a bug on some other instructions (e.g. JMP) if the associated shadow
// is poisoned.
//
// But there are differences too.
// The first and the major one: compiler instrumentation instead of
// binary instrumentation.
// This gives us much better register allocation, possible compiler
// optimizations and a fast start-up.
// But this brings the major issue as well: msan needs to see all program
// events, including system calls and reads/writes in system libraries,
// so we either need to compile *everything* with msan or use a binary
// translation component (e.g. DynamoRIO) to instrument pre-built libraries.
// Another difference from Memcheck is that we use 8 shadow bits per byte
// of application memory and use a direct shadow mapping.
// This greatly simplifies the instrumentation code and avoids races on
// shadow updates (Memcheck is single-threaded so races are not a concern there.
// Memcheck uses 2 shadow bits per byte with a slow path storage
// that uses 8 bits per byte).
//
// The dafault value of shadow is 0, which means "good" (not poisoned).
//
// Every module initializer should call __msan_init to ensure that the shadow
// memory is ready.
// On error, __msan_warning is called.
// Since parameters and return values may be passed via registers, we
// have a specialized thread-local shadow for return values (__msan_retval_tls)
// and parameters (__msan_param_tls).
///===----------------------------------------------------------------------===//

#define DEBUG_TYPE "msan"

#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ValueMap.h"
#include "llvm/Function.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Type.h"

using namespace llvm;

namespace {

/// MemorySanitizer: instrument the code in module to find uninitialized reads.
struct MemorySanitizer : public FunctionPass {
  MemorySanitizer() : FunctionPass(ID), TD(NULL) {  }
  const char *getPassName() const { return "MemorySanitizer"; }
  bool runOnFunction(Function &F);
  bool doInitialization(Module &M);
  static char ID;  // Pass identification, replacement for typeid.

  TargetData *TD;
  LLVMContext *C;
  Type *IntptrTy;
  // We store the shadow for parameters and retvals in separate TLS globals.
  GlobalVariable *ParamTLS;
  GlobalVariable *RetvalTLS;
  // The run-time callback to print a warning.
  Value *WarningFn;
  // The shadow address is computed as ApplicationAddress & ~ShadowMask.
  uint64_t ShadowMask;
};
}  // namespace

char MemorySanitizer::ID = 0;
INITIALIZE_PASS(MemorySanitizer, "msan",
    "MemorySanitizer: detects uninitialized reads.",
    false, false)

FunctionPass *llvm::createMemorySanitizerPass() {
  return new MemorySanitizer();
}

// Split the basic block and insert an if-then code.
// Before:
//   Head
//   SplitBefore
//   Tail
// After:
//   Head
//   if (Cmp)
//     NewBasicBlock
//   SplitBefore
//   Tail
//
// Returns the NewBasicBlock's terminator.
//
// FIXME: AddressSanitizer has a similar function.
// What is the best place to move it?
static BranchInst *splitBlockAndInsertIfThen(Value *Cmp) {
  Instruction *SplitBefore = cast<Instruction>(Cmp)->getNextNode();
  BasicBlock *Head = SplitBefore->getParent();
  BasicBlock *Tail = Head->splitBasicBlock(SplitBefore);
  TerminatorInst *HeadOldTerm = Head->getTerminator();
  LLVMContext &C = Head->getParent()->getParent()->getContext();
  BasicBlock *NewBasicBlock = BasicBlock::Create(C, "", Head->getParent());
  BranchInst *HeadNewTerm =
      BranchInst::Create(/*ifTrue*/NewBasicBlock, /*ifFalse*/Tail, Cmp);
  ReplaceInstWithInst(HeadOldTerm, HeadNewTerm);
  BranchInst *CheckTerm = BranchInst::Create(Tail, NewBasicBlock);
  return CheckTerm;
}

bool MemorySanitizer::doInitialization(Module &M) {
  TD = getAnalysisIfAvailable<TargetData>();
  if (!TD)
    return false;
  C = &(M.getContext());
  int PtrSize = TD->getPointerSizeInBits();
  switch (PtrSize) {
    case 64: ShadowMask = 1ULL << 46; break;
    case 32: ShadowMask = 1ULL << 31; break;
    default: llvm_unreachable("unsupported pointer size");
  }
  IntptrTy = Type::getIntNTy(*C, PtrSize);

  // Always insert a call to __msan_init into the module's CTORs.
  IRBuilder<> IRB(*C);
  Value *MsanInit = M.getOrInsertFunction("__msan_init", IRB.getVoidTy(), NULL);
  appendToGlobalCtors(M, cast<Function>(MsanInit), 0);

  // Create the callback.
  // FIXME: this function should have "Cold" calling conv,
  // which is not yet implemented. Alternatively, we may use llvm.trap.
  WarningFn = M.getOrInsertFunction("__msan_warning", IRB.getVoidTy(), NULL);
  // Create globals.
  RetvalTLS = new GlobalVariable(M, ArrayType::get(IRB.getInt64Ty(), 8),
    false, GlobalVariable::ExternalLinkage, 0, "__msan_retval_tls",
    0, GlobalVariable::GeneralDynamicTLSModel);
  ParamTLS = new GlobalVariable(M, ArrayType::get(IRB.getInt64Ty(), 1000),
    false, GlobalVariable::ExternalLinkage, 0, "__msan_param_tls", 0,
    GlobalVariable::GeneralDynamicTLSModel);
  return true;
}

namespace {
// This class does all the work for a given function.
struct MemorySanitizerVisitor : public InstVisitor<MemorySanitizerVisitor> {
  Function &F;
  MemorySanitizer &MS;
  SmallVector<PHINode *, 16> PHINodes;
  ValueMap<Value*, Value*> ShadowMap;

  struct ShadowAndInsertPoint {
    Instruction *Shadow;
    Instruction *InsertBefore;
    ShadowAndInsertPoint(Instruction *S, Instruction *I) :
      Shadow(S), InsertBefore(I) { }
    ShadowAndInsertPoint() : Shadow(0), InsertBefore(0) { }
  };
  SmallVector<ShadowAndInsertPoint, 16> InstrumentationSet;


  MemorySanitizerVisitor(Function &Func, MemorySanitizer &Msan) :
    F(Func), MS(Msan) { }

  bool runOnFunction() {
    if (!MS.TD) return false;
    // Iterate all BBs in depth-first order and create shadows instructions
    // for all instructions (where applicable).
    // For PHI nodes we create dummy shadow PHIs which will be finalized later.
    for (df_iterator<BasicBlock*> DI = df_begin(&F.getEntryBlock()),
         DE = df_end(&F.getEntryBlock()); DI != DE; ++DI) {
      BasicBlock *BB = *DI;
      visit(*BB);
    }

    // Finalize PHI nodes.
    for (size_t i = 0, n = PHINodes.size(); i < n; i++) {
      PHINode *PN = PHINodes[i];
      PHINode *PNS = cast<PHINode>(getShadow(PN));
      size_t NumValues = PN->getNumIncomingValues();
      for (size_t v = 0; v < NumValues; v++) {
        PNS->addIncoming(getShadow(PN, v), PN->getIncomingBlock(v));
      }
    }

    // Materialize checks.
    for (size_t i = 0, n = InstrumentationSet.size(); i < n; i++) {
      Instruction *Shadow = InstrumentationSet[i].Shadow;
      Instruction *InsertBefore = InstrumentationSet[i].InsertBefore;
      IRBuilder<> IRB(InsertBefore);
      Value *Cmp = IRB.CreateICmpNE(Shadow, getCleanShadow(Shadow), "_mscmp");
      Instruction *CheckTerm = splitBlockAndInsertIfThen(Cmp);
      IRBuilder<> IRB2(CheckTerm);
      IRB2.CreateCall(MS.WarningFn);
      DEBUG(dbgs() << "  SHAD : " << *Shadow << "\n");
      DEBUG(dbgs() << "  CHECK: " << *Cmp << "\n");
    }
    DEBUG(dbgs() << "DONE:\n" << F);
    return true;
  }

  // Compute the shadow type that corresponds to a given Value.
  Type *getShadowTy(Value *V) {
    Type *OrigTy = V->getType();
    if (!OrigTy->isSized()) {
      // dbgs() << " notSized() " << *V << "\n";
      return NULL;
    }
    uint32_t TypeSize = MS.TD->getTypeStoreSizeInBits(OrigTy);
    return IntegerType::get(*MS.C, TypeSize);
  }

  // Compute the shadow address that corresponds to a given application address.
  // Shadow = Addr & ~ShadowMask.
  Value *getShadowPtr(Value *Addr, Type *ShadowTy,
                      IRBuilder<> &IRB) {
    Value *ShadowLong =
        IRB.CreateAnd(IRB.CreatePointerCast(Addr, MS.IntptrTy),
                      ConstantInt::get(MS.IntptrTy, ~MS.ShadowMask));
    return IRB.CreateIntToPtr(ShadowLong, PointerType::get(ShadowTy, 0));
  }

  // Compute the shadow address for a given function argument.
  // Shadow = ParamTLS+ArgOffset.
  Value *getShadowPtrForArgument(Value *A, IRBuilder<> &IRB,
                                    int ArgOffset) {
    Value *Base = IRB.CreatePointerCast(MS.ParamTLS, MS.IntptrTy);
    Base = IRB.CreateAdd(Base, ConstantInt::get(MS.IntptrTy, ArgOffset));
    return IRB.CreateIntToPtr(Base, PointerType::get(getShadowTy(A), 0),
                              "_msarg");
  }

  // Compute the shadow address for a retval.
  Value *getShadowPtrForRetval(Value *A, IRBuilder<> &IRB) {
    Value *Base = IRB.CreatePointerCast(MS.RetvalTLS, MS.IntptrTy);
    return IRB.CreateIntToPtr(Base, PointerType::get(getShadowTy(A), 0),
                              "_msret");
  }

  void setShadow(Value *V, Value *SV) {
    assert(ShadowMap[V] == 0);
    ShadowMap[V] = SV;
  }

  // Create a clean (zero) shadow value for a given value.
  Value *getCleanShadow(Value *V) {
    Type *ShadowTy = getShadowTy(V);
    if (!ShadowTy)
      return NULL;
    return  Constant::getNullValue(ShadowTy);
  }

  // Get the shadow value for a given Value.
  Value *getShadow(Value *V) {
    if (Instruction *I = dyn_cast<Instruction>(V)) {
      // For instructions the shadow is already stored in the map.
      Value *Shadow = ShadowMap[V];
      if (!Shadow) {
        dbgs() << "No shadow: " << *V << "\n" << *(I->getParent());
        assert(Shadow);
      }
      return Shadow;
    }
    if (Argument *A = dyn_cast<Argument>(V)) {
      // For arguments we compute the shadow on demand and store it in the map.
      Value **ShadowPtr = &ShadowMap[V];
      if (*ShadowPtr)
        return *ShadowPtr;
      Function *F = A->getParent();
      IRBuilder<> EntryIRB(F->getEntryBlock().getFirstNonPHI());
      unsigned ArgOffset = 0;
      for (Function::arg_iterator AI = F->arg_begin(), AE = F->arg_end();
           AI != AE; ++AI) {
        if (!AI->getType()->isSized()) {
          DEBUG(dbgs() << "Arg is not sized\n");
          continue;
        }
        if (A == AI) {
          Value *Base = getShadowPtrForArgument(AI, EntryIRB, ArgOffset);
          *ShadowPtr = EntryIRB.CreateLoad(Base);
          DEBUG(dbgs() << "ARG "  << *AI << " ==> " << *ShadowPtr << "\n");
        }
        unsigned Size = MS.TD->getTypeAllocSize(AI->getType());
        ArgOffset += TargetData::RoundUpAlignment(Size, 8);
      }
      assert(*ShadowPtr);
      return *ShadowPtr;
    }
    // For everything else the shadow is zero.
    return getCleanShadow(V);
  }
  
  // Get the shadow for i-th argument of the instruction I.
  Value *getShadow(Instruction *I, int i) {
    return getShadow(I->getOperand(i));
  }

  // Remember the place where a check for ShadowVal should be inserted.
  void insertCheck(Value *ShadowVal, Instruction *InsertBefore) {
    if (!ShadowVal) return;
    Instruction *Shadow = dyn_cast<Instruction>(ShadowVal);
    if (!Shadow) return;
    InstrumentationSet.push_back(ShadowAndInsertPoint(Shadow, InsertBefore));
  }

  //------------------- Visitors.
  void visitLoadInst(LoadInst &I) {
    Type *LoadTy = I.getType();
    assert(LoadTy->isSized());
    uint32_t TypeSize = MS.TD->getTypeStoreSizeInBits(LoadTy);
    if (TypeSize != 8  && TypeSize != 16 &&
        TypeSize != 32 && TypeSize != 64 && TypeSize != 128) {
      // Ignore all unusual sizes.
      return ;
    }

    IRBuilder<> IRB(&I);
    Type *ShadowTy = getShadowTy(&I);
    Value *ShadowPtr = getShadowPtr(I.getPointerOperand(), ShadowTy, IRB);
    setShadow(&I, IRB.CreateLoad(ShadowPtr, "_msld"));
  }

  void visitStoreInst(StoreInst &I) {
    IRBuilder<> IRB(&I);
    Value *Val = I.getValueOperand();
    Value *Addr = I.getPointerOperand();
    Value *Shadow = getShadow(Val);
    Value *ShadowPtr = getShadowPtr(Addr, Shadow->getType(), IRB);

    StoreInst *NewSI = IRB.CreateStore(Shadow, ShadowPtr);
    DEBUG(dbgs() << "  STORE: " << *NewSI << "\n");
    // If the store is volatile, add a check.
    if (I.isVolatile())
      insertCheck(Shadow, &I);
  }

  void visitSExtInst(SExtInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateSExt(getShadow(&I, 0), I.getType(), "_msprop"));
  }

  void visitZExtInst(ZExtInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateZExt(getShadow(&I, 0), I.getType(), "_msprop"));
  }

  void visitTruncInst(TruncInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateTrunc(getShadow(&I, 0), I.getType(), "_msprop"));
  }

  void visitAnd(BinaryOperator &I) {
    IRBuilder<> IRB(&I);
    //  "And" of 0 and a poisoned value results in unpoisoned value.
    //  1&1 => 1;     0&1 => 0;     p&1 => p;
    //  1&0 => 0;     0&0 => 0;     p&0 => 0;
    //  1&p => p;     0&p => 0;     p&p => p;
    //  S = (S1 & S2) | (V1 & S2) | (S1 & V2)
    Value *S1 = getShadow(&I, 0);
    Value *S2 = getShadow(&I, 1);
    Value *V1 = I.getOperand(0);
    Value *V2 = I.getOperand(1);
    if (V1->getType() != S1->getType()) {
      V1 = IRB.CreateIntCast(V1, S1->getType(), false);
      V2 = IRB.CreateIntCast(V2, S2->getType(), false);
    }
    Value *S1S2 = IRB.CreateAnd(S1, S2);
    Value *V1S2 = IRB.CreateAnd(V1, S2);
    Value *S1V2 = IRB.CreateAnd(S1, V2);
    setShadow(&I, IRB.CreateOr(S1S2, IRB.CreateOr(V1S2, S1V2)));
  }

  void visitOr(BinaryOperator &I) {
    IRBuilder<> IRB(&I);
    //  "Or" of 1 and a poisoned value results in unpoisoned value.
    //  1|1 => 1;     0|1 => 1;     p|1 => 1;
    //  1|0 => 1;     0|0 => 0;     p|0 => p;
    //  1|p => 1;     0|p => p;     p|p => p;
    //  S = (S1 & S2) | (~V1 & S2) | (S1 & ~V2)
    Value *S1 = getShadow(&I, 0);
    Value *S2 = getShadow(&I, 1);
    Value *V1 = IRB.CreateNot(I.getOperand(0));
    Value *V2 = IRB.CreateNot(I.getOperand(1));
    if (V1->getType() != S1->getType()) {
      V1 = IRB.CreateIntCast(V1, S1->getType(), false);
      V2 = IRB.CreateIntCast(V2, S2->getType(), false);
    }
    Value *S1S2 = IRB.CreateAnd(S1, S2);
    Value *V1S2 = IRB.CreateAnd(V1, S2);
    Value *S1V2 = IRB.CreateAnd(S1, V2);
    setShadow(&I, IRB.CreateOr(S1S2, IRB.CreateOr(V1S2, S1V2)));
  }

  void handleShadowOr(BinaryOperator &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I,  IRB.CreateOr(getShadow(&I, 0), getShadow(&I, 1), "_msprop"));
  }

  void visitFAdd(BinaryOperator &I) { handleShadowOr(I); }
  void visitFSub(BinaryOperator &I) { handleShadowOr(I); }
  void visitFMul(BinaryOperator &I) { handleShadowOr(I); }
  void visitAdd(BinaryOperator &I) { handleShadowOr(I); }
  void visitSub(BinaryOperator &I) { handleShadowOr(I); }
  void visitXor(BinaryOperator &I) { handleShadowOr(I); }

  void handleShift(BinaryOperator &I) {
    IRBuilder<> IRB(&I);
    // If any of the S2 bits are poisoned, the whole thing is poisoned.
    // Otherwise perform the same shift on S1.
    Value *S1 = getShadow(&I, 0);
    Value *S2 = getShadow(&I, 1);
    Value *S2Conv = IRB.CreateSExt(IRB.CreateICmpNE(S2, getCleanShadow(S2)),
                                   S2->getType());
    Value *V2 = I.getOperand(1);
    Value *Shift = IRB.CreateBinOp(I.getOpcode(), S1, V2);
    setShadow(&I, IRB.CreateOr(Shift, S2Conv));
  }

  void visitShl(BinaryOperator &I) { handleShift(I); }
  void visitAShr(BinaryOperator &I) { handleShift(I); }
  void visitLShr(BinaryOperator &I) { handleShift(I); }

  void visitCallInst(CallInst &I) {
    IRBuilder<> IRB(&I);
    size_t n = I.getNumArgOperands();
    unsigned ArgOffset = 0;
    for (size_t i = 0; i < n; i++) {
      Value *A = I.getArgOperand(i);
      if (!A->getType()->isSized()) {
        DEBUG(dbgs() << "Arg " << i << " is not sized: " << I << "\n");
        continue;
      }
      unsigned Size = MS.TD->getTypeAllocSize(A->getType());
      Value *Base = getShadowPtrForArgument(A, IRB, ArgOffset);
      Value *Store = IRB.CreateStore(getShadow(A), Base);
      ArgOffset += TargetData::RoundUpAlignment(Size, 8);
      DEBUG(dbgs() << "  ASHD: " << *Store << "\n");
    }
    // Now, get the shadow for the RetVal.
    if (I.getType()->isSized()) {
      IRBuilder<> IRBAfter(I.getNextNode());
      Value *Base = getShadowPtrForRetval(&I, IRBAfter);
      setShadow(&I, IRBAfter.CreateLoad(Base));
    }

    // Allow only tail calls with the same types, otherwise
    // we may have a false positive: shadow for a non-void RetVal
    // will get propagated to a void RetVal.
    if (I.isTailCall() && I.getType() != I.getParent()->getType())
      I.setTailCall(false);
  }

  void visitBrInst(BranchInst &I) { }

  void visitReturnInst(ReturnInst &I) {
    IRBuilder<> IRB(&I);
    if (Value *RetVal = I.getReturnValue()) {
      // Set the shadow for the RetVal.
      Value *Base = getShadowPtrForRetval(RetVal, IRB);
      IRB.CreateStore(getShadow(RetVal), Base);
    }
  }

  void visitPHINode(PHINode &I) {
    IRBuilder<> IRB(&I);
    PHINode *PNS = IRB.CreatePHI(getShadowTy(&I), I.getNumIncomingValues(),
                                 "_msphi");
    PHINodes.push_back(&I);
    setShadow(&I, PNS);
  }

  void visitAllocaInst(AllocaInst &I) {
    // FIXME: poison the allocated object. Not implemented yet.
    setShadow(&I, getCleanShadow(&I));
  }

  void visitInstruction(Instruction &I) {
    // Everything else: stop propagating and check for poisoned shadow.
    DEBUG(dbgs() << "DEFAULT: " << I << "\n");
    for (size_t i = 0, n = I.getNumOperands(); i < n; i++)
      insertCheck(getShadow(&I, i), &I);
    setShadow(&I, getCleanShadow(&I));
  }
};

}  // namespace

bool MemorySanitizer::runOnFunction(Function &F) {
  MemorySanitizerVisitor Visitor(F, *this);
  return Visitor.runOnFunction();
}
