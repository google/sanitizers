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
#include "llvm/InlineAsm.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/IRBuilder.h"
#include "llvm/LLVMContext.h"
#include "llvm/MDBuilder.h"
#include "llvm/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Type.h"

using namespace llvm;

static cl::opt<bool> ClUseTrap("msan-use-trap",
       cl::desc("use trap (ud2) instead of __msan_warning"),
       cl::Hidden, cl::init(true));
static cl::opt<bool> ClPoisonStack("msan-poison-stack",
       cl::desc("poison uninitialized stack variables"),
       cl::Hidden, cl::init(true));
static cl::opt<int> ClPoisonStackPattern("msan-poison-stack-pattern",
       cl::desc("poison uninitialized stack variables with the given patter"),
       cl::Hidden, cl::init(0xff));

static cl::opt<bool> ClHandleICmp("msan-handle-icmp",
       cl::desc("propagate shadow through ICmpEQ and ICmpNE"),
       cl::Hidden, cl::init(true));

static cl::opt<bool> ClDumpStrictInstructions("msan-dump-strict-instructions",
       cl::desc("print out instructions with default strict semantics"),
       cl::Hidden, cl::init(false));

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
  // Branch weights for error reporting.
  MDNode *ColdCallWeights;
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
static BranchInst *splitBlockAndInsertIfThen(Value *Cmp,
    MDNode *BranchWeights = 0) {
  Instruction *SplitBefore = cast<Instruction>(Cmp)->getNextNode();
  BasicBlock *Head = SplitBefore->getParent();
  BasicBlock *Tail = Head->splitBasicBlock(SplitBefore);
  TerminatorInst *HeadOldTerm = Head->getTerminator();
  LLVMContext &C = Head->getParent()->getParent()->getContext();
  BasicBlock *NewBasicBlock = BasicBlock::Create(C, "", Head->getParent());
  BranchInst *HeadNewTerm =
      BranchInst::Create(/*ifTrue*/NewBasicBlock, /*ifFalse*/Tail, Cmp);
  HeadNewTerm->setMetadata(LLVMContext::MD_prof, BranchWeights);
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

  ColdCallWeights = MDBuilder(*C).createBranchWeights(1, 1000);

  // Always insert a call to __msan_init into the module's CTORs.
  IRBuilder<> IRB(*C);
  Value *MsanInit = M.getOrInsertFunction("__msan_init", IRB.getVoidTy(), NULL);
  appendToGlobalCtors(M, cast<Function>(MsanInit), 0);

  // Create the callback.
  // FIXME: this function should have "Cold" calling conv,
  // which is not yet implemented. Alternatively, we may use llvm.trap.
  if (ClUseTrap) {
    // WarningFn = Intrinsic::getDeclaration(&M, Intrinsic::trap);
    // We use inline asm because Intrinsic::trap is treated as never return.
    WarningFn = InlineAsm::get(FunctionType::get(Type::getVoidTy(*C), false),
                                  StringRef("ud2"), StringRef(""), true);
  } else {
    WarningFn = M.getOrInsertFunction("__msan_warning", IRB.getVoidTy(), NULL);
  }
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
  Value *NextVAArgShadowPtr;

  struct ShadowAndInsertPoint {
    Instruction *Shadow;
    Instruction *OrigIns;
    ShadowAndInsertPoint(Instruction *S, Instruction *I) :
      Shadow(S), OrigIns(I) { }
    ShadowAndInsertPoint() : Shadow(0), OrigIns(0) { }
  };
  SmallVector<ShadowAndInsertPoint, 16> InstrumentationSet;


  MemorySanitizerVisitor(Function &Func, MemorySanitizer &Msan) :
    F(Func), MS(Msan), NextVAArgShadowPtr(0) { }

  void initVAArgs(IRBuilder<> &IRB) {
    assert(!NextVAArgShadowPtr);
    unsigned FixedArgsSize = 0;
    for (Function::arg_iterator AI = F.arg_begin(); AI != F.arg_end();
         ++AI) {
      if (!AI->getType()->isSized()) {
        DEBUG(dbgs() << "Arg is not sized\n");
        continue;
      }
      unsigned Size = MS.TD->getTypeAllocSize(AI->getType());
      FixedArgsSize += TargetData::RoundUpAlignment(Size, 8);
    }
    NextVAArgShadowPtr = IRB.CreateAlloca(Type::getInt8PtrTy(*MS.C));
    IRB.CreateStore(IRB.CreateConstGEP1_32(IRB.CreatePointerCast(MS.ParamTLS,
                Type::getInt8PtrTy(*MS.C)), FixedArgsSize), NextVAArgShadowPtr);
  }

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
      Instruction *OrigIns = InstrumentationSet[i].OrigIns;
      IRBuilder<> IRB(OrigIns);
      Value *Cmp = IRB.CreateICmpNE(Shadow, getCleanShadow(Shadow), "_mscmp");
      Instruction *CheckTerm = splitBlockAndInsertIfThen(Cmp, MS.ColdCallWeights);
      IRBuilder<> IRB2(CheckTerm);
      CallInst *Call = IRB2.CreateCall(MS.WarningFn);
      Call->setDebugLoc(OrigIns->getDebugLoc());
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
    // For integer type, shadow is the same as the original type.
    // This may return weird-sized types like i1.
    if (IntegerType* it = dyn_cast<IntegerType>(OrigTy))
      return it;
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

  Value *getNextVAArgShadow(Instruction *I) {
    IRBuilder<> IRB(I);

    Type *ArgType = I->getType();
    unsigned ArgSize = MS.TD->getTypeAllocSize(ArgType);

    Value* Ptr = IRB.CreateLoad(NextVAArgShadowPtr);
    Value* NextPtr = IRB.CreateConstGEP1_32(Ptr, TargetData::RoundUpAlignment(ArgSize, 8));
    IRB.CreateStore(NextPtr, NextVAArgShadowPtr);

    Type *ShadowTy = getShadowTy(I);
    Value *ShadowPtr = IRB.CreatePointerCast(Ptr,PointerType::get(ShadowTy, 0));
    return IRB.CreateLoad(ShadowPtr, "_msva_arg");
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
  void insertCheck(Value *ShadowVal, Instruction *OrigIns) {
    if (!ShadowVal) return;
    Instruction *Shadow = dyn_cast<Instruction>(ShadowVal);
    if (!Shadow) return;
    InstrumentationSet.push_back(ShadowAndInsertPoint(Shadow, OrigIns));
  }

  //------------------- Visitors.
  void visitLoadInst(LoadInst &I) {
    Type *LoadTy = I.getType();
    assert(LoadTy->isSized());
    uint32_t TypeSize = MS.TD->getTypeStoreSizeInBits(LoadTy);
    if (TypeSize != 8  && TypeSize != 16 &&
        TypeSize != 32 && TypeSize != 64 && TypeSize != 128) {
      // Ignore all unusual sizes.
      setShadow(&I, getCleanShadow(dyn_cast<Value>(&I)));
      return ;
    }
    // TODO: consider inserting a check of the pointer operand (for both load
    // and store)?
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

  // Casts.
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

  void visitBitCastInst(BitCastInst &I) {
    setShadow(&I, getShadow(&I, 0));
  }

  void visitPtrToIntInst(PtrToIntInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateIntCast(getShadow(&I, 0), getShadowTy(&I), false,
            "_msprop_ptrtoint"));
  }

  void visitIntToPtrInst(IntToPtrInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateIntCast(getShadow(&I, 0), getShadowTy(&I), false,
            "_msprop_inttoptr"));
  }

  void visitFPToSIInst(CastInst& I) { handleShadowOr(I); }
  void visitFPToUIInst(CastInst& I) { handleShadowOr(I); }
  void visitSIToFPInst(CastInst& I) { handleShadowOr(I); }
  void visitUIToFPInst(CastInst& I) { handleShadowOr(I); }
  void visitFPExtInst(CastInst& I) { handleShadowOr(I); }
  void visitFPTruncInst(CastInst& I) { handleShadowOr(I); }

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

  void handleShadowOr(Instruction &I) {
    IRBuilder<> IRB(&I);
    Value* temp = getShadow(&I, 0);
    for (unsigned op = 1; op < I.getNumOperands(); ++op)
      temp = IRB.CreateOr(temp,
          IRB.CreateIntCast(getShadow(&I, op), temp->getType(), false),
          "_msprop");
    temp = IRB.CreateIntCast(temp, getShadowTy(&I), false);
    setShadow(&I, temp);
  }

  void visitFAdd(BinaryOperator &I) { handleShadowOr(I); }
  void visitFSub(BinaryOperator &I) { handleShadowOr(I); }
  void visitFMul(BinaryOperator &I) { handleShadowOr(I); }
  void visitAdd(BinaryOperator &I) { handleShadowOr(I); }
  void visitSub(BinaryOperator &I) { handleShadowOr(I); }
  void visitXor(BinaryOperator &I) { handleShadowOr(I); }
  void visitMul(BinaryOperator &I) { handleShadowOr(I); }

  void handleDiv(Instruction &I) {
    IRBuilder<> IRB(&I);
    // Strict on the second argument.
    insertCheck(getShadow(&I, 1), &I);
    setShadow(&I, getShadow(&I, 0));
  }

  void visitUDiv(BinaryOperator &I) { handleDiv(I); }
  void visitSDiv(BinaryOperator &I) { handleDiv(I); }
  void visitFDiv(BinaryOperator &I) { handleDiv(I); }
  void visitURem(BinaryOperator &I) { handleDiv(I); }
  void visitSRem(BinaryOperator &I) { handleDiv(I); }
  void visitFRem(BinaryOperator &I) { handleDiv(I); }

  void handleEqualityComparison(ICmpInst &I) {
    IRBuilder<> IRB(&I);
    Value *A = I.getOperand(0);
    Value *B = I.getOperand(1);
    Value *Sa = getShadow(A);
    Value *Sb = getShadow(B);
    if (A->getType()->isPointerTy())
      A = IRB.CreatePointerCast(A, MS.IntptrTy);
    if (B->getType()->isPointerTy())
      B = IRB.CreatePointerCast(B, MS.IntptrTy);
    // A == B  <==>  (C = A^B) == 0
    // A != B  <==>  (C = A^B) != 0
    // Sc = Sa | Sb
    Value *C = IRB.CreateXor(A, B);
    Value *Sc = IRB.CreateOr(Sa, Sb);
    // Now dealing with i = (C == 0) comparison (or C != 0, does not matter now)
    // Result is defined if one of the following is true
    // * there is a defined 1 bit in C
    // * C is fully defined and == 0
    // Si = !(C & ~Sc) && Sc
    Value* Zero = ConstantInt::get(A->getType(), 0);
    Value* MinusOne = ConstantInt::get(A->getType(), -1, /* isSigned */ true);
    Value* Si = IRB.CreateAnd(IRB.CreateICmpNE(Sc, Zero),
        IRB.CreateICmpEQ(IRB.CreateAnd(IRB.CreateXor(Sc, MinusOne), C), Zero));
    Si->setName("_msprop_icmp");
    setShadow(&I, Si);
  }

  void visitICmpInst(ICmpInst &I) {
    if (ClHandleICmp && I.isEquality())
      handleEqualityComparison(I);
    else
      handleShadowOr(I);
  }

  void visitFCmpInst(FCmpInst &I) {
    handleShadowOr(I);
  }

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

  void handleMemSet(MemSetInst &I) {
    IRBuilder<> IRB(&I);
    Value *Ptr = I.getArgOperand(0);
    Value *Val = I.getArgOperand(1);
    Value *ShadowPtr = getShadowPtr(Ptr, Val->getType(), IRB);
    Value *ShadowVal = getCleanShadow(Val);
    Value *Size = I.getArgOperand(2);
    unsigned Align = I.getAlignment();
    bool isVolatile = I.isVolatile();

    IRB.CreateMemSet(ShadowPtr, ShadowVal, Size, Align, isVolatile);
  }

  void handleMemCpy(MemCpyInst &I) {
    IRBuilder<> IRB(&I);
    Value *Dst = I.getArgOperand(0);
    Value *Src = I.getArgOperand(1);
    Type *ElementType = dyn_cast<PointerType>(Dst->getType())->getElementType();
    Value *ShadowDst = getShadowPtr(Dst, ElementType, IRB);
    Value *ShadowSrc = getShadowPtr(Src, ElementType, IRB);
    Value *Size = I.getArgOperand(2);
    unsigned Align = I.getAlignment();
    bool isVolatile = I.isVolatile();

    IRB.CreateMemCpy(ShadowDst, ShadowSrc, Size, Align, isVolatile);
  }

  void handleMemMove(MemMoveInst &I) {
    IRBuilder<> IRB(&I);
    Value *Dst = I.getArgOperand(0);
    Value *Src = I.getArgOperand(1);
    Type *ElementType = dyn_cast<PointerType>(Dst->getType())->getElementType();
    Value *ShadowDst = getShadowPtr(Dst, ElementType, IRB);
    Value *ShadowSrc = getShadowPtr(Src, ElementType, IRB);
    Value *Size = I.getArgOperand(2);
    unsigned Align = I.getAlignment();
    bool isVolatile = I.isVolatile();

    IRB.CreateMemMove(ShadowDst, ShadowSrc, Size, Align, isVolatile);
  }

  void handleVAStart(IntrinsicInst &I) {
    IRBuilder<> IRB(&I);

    initVAArgs(IRB);

    Value *VAListTag = I.getArgOperand(0);
    Value *ShadowPtr = getShadowPtr(VAListTag, IRB.getInt8Ty(), IRB);

    // Unpoison the whole __va_list_tag.
    // FIXME: magic constants.
    IRB.CreateMemSet(ShadowPtr, Constant::getNullValue(IRB.getInt8Ty()), 24, 16, false);
  }

  void visitVAArg(VAArgInst &I) {
    setShadow(&I, getNextVAArgShadow(&I));
  }

  void visitCallInst(CallInst &I) {
    if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(&I)) {
      if (MemSetInst* MemSet = dyn_cast<MemSetInst>(&I))
        handleMemSet(*MemSet);
      else if (MemCpyInst* MemCpy = dyn_cast<MemCpyInst>(&I))
        handleMemCpy(*MemCpy);
      else if (MemMoveInst* MemMove = dyn_cast<MemMoveInst>(&I))
        handleMemMove(*MemMove);
      else if (II->getIntrinsicID() == llvm::Intrinsic::vastart)
        handleVAStart(*II);
      else
        // Unhandled intrinsic: mark retval as clean.
        visitInstruction(I);
      return;
    }
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
      IRBuilder<> IRBBefore(&I);
      // Untill we have full dynamic coverage, make sure the retval shadow is 0.
      Value *Base = getShadowPtrForRetval(&I, IRBBefore);
      IRBBefore.CreateStore(getCleanShadow(&I), Base);
      IRBuilder<> IRBAfter(I.getNextNode());
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
    setShadow(&I, getCleanShadow(&I));
    if (ClPoisonStack) {
      IRBuilder<> IRB(I.getNextNode());
      Value *ShadowBase = getShadowPtr(&I, Type::getInt8PtrTy(*MS.C), IRB);
      uint64_t Size = MS.TD->getTypeAllocSize(I.getAllocatedType());
      IRB.CreateMemSet(ShadowBase, IRB.getInt8(ClPoisonStackPattern),
                       Size, I.getAlignment());
    }
  }

  void visitSelectInst(SelectInst& I) {
    IRBuilder<> IRB(&I);
    setShadow(&I,  IRB.CreateSelect(I.getCondition(),
            getShadow(I.getTrueValue()), getShadow(I.getFalseValue()),
            "_msprop"));
  }

  void visitLandingPadInst(LandingPadInst &I) {
    // Do nothing.
    // See http://code.google.com/p/memory-sanitizer/issues/detail?id=1
    setShadow(&I, getCleanShadow(&I));
  }

  void visitGetElementPtrInst(GetElementPtrInst &I) {
    handleShadowOr(I);
  }

  void dumpInst(Instruction &I) {
    if (CallInst* CI = dyn_cast<CallInst>(&I)) {
      errs() << "ZZZ call " << CI->getCalledFunction()->getName() << "\n";
    } else {
      errs() << "ZZZ " << I.getOpcodeName() << "\n";
    }
    errs() << "QQQ " << I << "\n";
  }

  void visitInstruction(Instruction &I) {
    // Everything else: stop propagating and check for poisoned shadow.
    if (ClDumpStrictInstructions)
      dumpInst(I);
    DEBUG(dbgs() << "DEFAULT: " << I << "\n");
    for (size_t i = 0, n = I.getNumOperands(); i < n; i++)
      insertCheck(getShadow(&I, i), &I);
    setShadow(&I, getCleanShadow(&I));
  }
};

}  // namespace

bool MemorySanitizer::runOnFunction(Function &F) {
  MemorySanitizerVisitor Visitor(F, *this);
  F.removeAttribute(~0, Attribute::ReadOnly | Attribute::ReadNone);
  return Visitor.runOnFunction();
}
