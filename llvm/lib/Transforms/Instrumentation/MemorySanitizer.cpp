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
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "msan"

#include "BlackList.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ValueMap.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Function.h"
#include "llvm/InlineAsm.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/IRBuilder.h"
#include "llvm/LLVMContext.h"
#include "llvm/MDBuilder.h"
#include "llvm/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/DataLayout.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Type.h"

using namespace llvm;

// This is an important flag that makes the reports much more informative
// at the cost of greater slowdown. Not fully implemented yet.
// FIXME: this should be a top-level clang flag, e.g. -fmemory-sanitizer-full.
static cl::opt<bool> ClTrackOrigins("msan-track-origins",
       cl::desc("Track origins (allocation sites) of poisoned memory"),
       cl::Hidden, cl::init(false));
static cl::opt<bool> ClUseTrap("msan-use-trap",
       cl::desc("use trap (ud2) instead of __msan_warning"),
       cl::Hidden, cl::init(true));
static cl::opt<bool> ClPoisonStack("msan-poison-stack",
       cl::desc("poison uninitialized stack variables"),
       cl::Hidden, cl::init(true));
static cl::opt<bool> ClPoisonStackWithCall("msan-poison-stack-with-call",
       cl::desc("poison uninitialized stack variables with a call"),
       cl::Hidden, cl::init(false));
static cl::opt<int> ClPoisonStackPattern("msan-poison-stack-pattern",
       cl::desc("poison uninitialized stack variables with the given patter"),
       cl::Hidden, cl::init(0xff));

static cl::opt<bool> ClHandleICmp("msan-handle-icmp",
       cl::desc("propagate shadow through ICmpEQ and ICmpNE"),
       cl::Hidden, cl::init(true));

// This flag controls whether we check the shadow of the address operand
// of load or store.
// Such bugs are very rare, since load from a garbage address typically results
// in SEGV, but still happen (e.g. only lower bits of address are garbage,
// or the access happens early at program startup where malloc-ed memory is more
// likely to be zeroed.
// As of 2012-08-28 this flag adds 20% slowdown.
static cl::opt<bool> ClTrapOnDirtyAccess("msan-trap-on-dirty-access",
       cl::desc("trap on access to a pointer which has poisoned shadow"),
       cl::Hidden, cl::init(true));

static cl::opt<bool> ClDumpStrictInstructions("msan-dump-strict-instructions",
       cl::desc("print out instructions with default strict semantics"),
       cl::Hidden, cl::init(false));

static cl::opt<std::string>  ClBlackListFile("msan-blacklist",
       cl::desc("File containing the list of functions where MemorySanitizer "
                "should not report bugs"), cl::Hidden);

namespace {

/// MemorySanitizer: instrument the code in module to find uninitialized reads.
struct MemorySanitizer : public FunctionPass {
  MemorySanitizer() : FunctionPass(ID), TD(NULL) {  }
  const char *getPassName() const { return "MemorySanitizer"; }
  bool runOnFunction(Function &F);
  bool doInitialization(Module &M);
  static char ID;  // Pass identification, replacement for typeid.

  DataLayout *TD;
  LLVMContext *C;
  Type *IntptrTy;
  Type *OriginTy;
  // We store the shadow for parameters and retvals in separate TLS globals.
  GlobalVariable *ParamTLS, *ParamOriginTLS;
  GlobalVariable *RetvalTLS, *RetvalOriginTLS;
  GlobalVariable *VAArgTLS;
  GlobalVariable *VAArgOverflowSizeTLS;
  GlobalVariable *OriginTLS;
  // The run-time callback to print a warning.
  Value *WarningFn;
  Value *MsanCopyOriginFn;
  Value *MsanSetAllocaOriginFn;
  Value *MsanPoisonStackFn;
  Value *MemmoveFn, *MemcpyFn, *MemsetFn;
  // ShadowAddr is computed as ApplicationAddr & ~ShadowMask.
  uint64_t ShadowMask;
  // OriginAddr is computed as (ShadowAddr+Offset) & ~3ULL
  uint64_t OriginOffset;
  // Branch weights for error reporting.
  MDNode *ColdCallWeights;
  OwningPtr<BlackList> BL;
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

// Create a non-const global for Str so that we can pass it to the run-time lib.
static GlobalVariable *createPrivateNonConstGlobalForString(Module &M, StringRef Str) {
  Constant *StrConst = ConstantDataArray::getString(M.getContext(), Str);
  return new GlobalVariable(M, StrConst->getType(), /*isConstant=*/false,
                            GlobalValue::PrivateLinkage, StrConst, "");
}


bool MemorySanitizer::doInitialization(Module &M) {
  TD = getAnalysisIfAvailable<DataLayout>();
  if (!TD)
    return false;
  BL.reset(new BlackList(ClBlackListFile));
  C = &(M.getContext());
  int PtrSize = TD->getPointerSizeInBits(/* AddressSpace */0);
  switch (PtrSize) {
    case 64:
      ShadowMask = 1ULL << 46;
      OriginOffset = 1ULL << 45;
      break;
    case 32:
      ShadowMask = 1ULL << 31;
      OriginOffset = 1ULL << 30;
      break;
    default: llvm_unreachable("unsupported pointer size");
  }
  IntptrTy = Type::getIntNTy(*C, PtrSize);
  OriginTy = Type::getIntNTy(*C, 32);

  ColdCallWeights = MDBuilder(*C).createBranchWeights(1, 1000);

  // Insert a call to __msan_init/__msan_track_origins into the module's CTORs.
  IRBuilder<> IRB(*C);
  appendToGlobalCtors(M, cast<Function>(M.getOrInsertFunction(
        "__msan_init", IRB.getVoidTy(), NULL)), 0);

  new GlobalVariable(M, IRB.getInt32Ty(), true, GlobalValue::LinkOnceODRLinkage,
                     ConstantInt::get(IRB.getInt32Ty(), ClTrackOrigins),
                     "__msan_track_origins");

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
  MsanCopyOriginFn = M.getOrInsertFunction("__msan_copy_origin",
    IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy, NULL);
  MsanSetAllocaOriginFn = M.getOrInsertFunction("__msan_set_alloca_origin",
    IRB.getVoidTy(),
    IRB.getInt8PtrTy(), IntptrTy, IRB.getInt8PtrTy(), NULL);
  MsanPoisonStackFn = M.getOrInsertFunction("__msan_poison_stack",
    IRB.getVoidTy(), IRB.getInt8PtrTy(), IntptrTy, NULL);
  MemmoveFn = M.getOrInsertFunction("memmove",
    IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy, NULL);
  MemcpyFn = M.getOrInsertFunction("memcpy",
    IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy, NULL);
  MemsetFn = M.getOrInsertFunction("memset",
    IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IRB.getInt32Ty(), IntptrTy, NULL);
  // Create globals.
  RetvalTLS = new GlobalVariable(M, ArrayType::get(IRB.getInt64Ty(), 8),
    false, GlobalVariable::ExternalLinkage, 0, "__msan_retval_tls",
    0, GlobalVariable::GeneralDynamicTLSModel);
  RetvalOriginTLS = new GlobalVariable(M, OriginTy,
    false, GlobalVariable::ExternalLinkage, 0, "__msan_retval_origin_tls",
    0, GlobalVariable::GeneralDynamicTLSModel);

  ParamTLS = new GlobalVariable(M, ArrayType::get(IRB.getInt64Ty(), 1000),
    false, GlobalVariable::ExternalLinkage, 0, "__msan_param_tls", 0,
    GlobalVariable::GeneralDynamicTLSModel);
  ParamOriginTLS = new GlobalVariable(M, ArrayType::get(OriginTy, 1000),
    false, GlobalVariable::ExternalLinkage, 0, "__msan_param_origin_tls", 0,
    GlobalVariable::GeneralDynamicTLSModel);

  VAArgTLS = new GlobalVariable(M, ArrayType::get(IRB.getInt64Ty(), 1000),
    false, GlobalVariable::ExternalLinkage, 0, "__msan_va_arg_tls", 0,
    GlobalVariable::GeneralDynamicTLSModel);
  VAArgOverflowSizeTLS = new GlobalVariable(M, IRB.getInt64Ty(),
    false, GlobalVariable::ExternalLinkage, 0,
    "__msan_va_arg_overflow_size_tls", 0,
    GlobalVariable::GeneralDynamicTLSModel);
  OriginTLS = new GlobalVariable(M, IRB.getInt32Ty(),
    false, GlobalVariable::ExternalLinkage, 0, "__msan_origin_tls", 0,
    GlobalVariable::GeneralDynamicTLSModel);
  return true;
}

namespace {
// This class does all the work for a given function.
struct MemorySanitizerVisitor : public InstVisitor<MemorySanitizerVisitor> {
  Function &F;
  MemorySanitizer &MS;
  SmallVector<PHINode *, 16> ShadowPHINodes, OriginPHINodes;
  ValueMap<Value*, Value*> ShadowMap, OriginMap;
  Value *VAArgTLSCopy;
  Value *VAArgOverflowSize;
  bool InsertChecks;

  static const unsigned AMD64GpEndOffset = 48; // AMD64 ABI Draft 0.99.6 p3.5.7
  static const unsigned AMD64FpEndOffset = 176;

  struct ShadowOriginAndInsertPoint {
    Instruction *Shadow;
    Instruction *Origin;
    Instruction *OrigIns;
    ShadowOriginAndInsertPoint(Instruction *S, Instruction *O, Instruction *I) :
      Shadow(S), Origin(O), OrigIns(I) { }
    ShadowOriginAndInsertPoint() : Shadow(0), Origin(0), OrigIns(0) { }
  };
  SmallVector<ShadowOriginAndInsertPoint, 16> InstrumentationSet;

  SmallVector<CallInst*, 16> VAStartInstrumentationSet;


  MemorySanitizerVisitor(Function &Func, MemorySanitizer &Msan) :
    F(Func), MS(Msan), VAArgTLSCopy(0), VAArgOverflowSize(0) {
    InsertChecks = !MS.BL->isIn(F);
    if (!InsertChecks)
      dbgs() << "MemorySanitizer is not inserting checks into "
             << F.getName() << "\n";
  }

  LLVM_ATTRIBUTE_NOINLINE
  void materializeChecks() {
    for (size_t i = 0, n = InstrumentationSet.size(); i < n; i++) {
      Instruction *Shadow = InstrumentationSet[i].Shadow;
      Instruction *OrigIns = InstrumentationSet[i].OrigIns;
      IRBuilder<> IRB(OrigIns);
      DEBUG(dbgs() << "  SHAD0 : " << *Shadow << "\n");
      Value *ConvertedShadow = convertToShadowTyNoVec(Shadow, IRB);
      DEBUG(dbgs() << "  SHAD1 : " << *ConvertedShadow << "\n");
      Value *Cmp = IRB.CreateICmpNE(ConvertedShadow,
                                    getCleanShadow(ConvertedShadow), "_mscmp");
      Instruction *CheckTerm =
          splitBlockAndInsertIfThen(Cmp, MS.ColdCallWeights);

      IRB.SetInsertPoint(CheckTerm);
      if (ClTrackOrigins) {
        Instruction *Origin = InstrumentationSet[i].Origin;
        IRB.CreateStore(Origin ? (Value*)Origin : (Value*)IRB.getInt32(0),
            MS.OriginTLS);
      }
      CallInst *Call = IRB.CreateCall(MS.WarningFn);
      Call->setDebugLoc(OrigIns->getDebugLoc());
      DEBUG(dbgs() << "  CHECK: " << *Cmp << "\n");
    }
    DEBUG(dbgs() << "DONE:\n" << F);
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
    for (size_t i = 0, n = ShadowPHINodes.size(); i < n; i++) {
      PHINode *PN = ShadowPHINodes[i];
      PHINode *PNS = cast<PHINode>(getShadow(PN));
      PHINode *PNO = ClTrackOrigins ? cast<PHINode>(getOrigin(PN)) : 0;
      size_t NumValues = PN->getNumIncomingValues();
      for (size_t v = 0; v < NumValues; v++) {
        PNS->addIncoming(getShadow(PN, v), PN->getIncomingBlock(v));
        if (PNO)
          PNO->addIncoming(getOrigin(PN, v), PN->getIncomingBlock(v));
      }
    }

    if (!VAStartInstrumentationSet.empty()) {
      // If there is a va_start in this function, make a backup copy of
      // va_arg_tls somewhere in the function entry block.
      IRBuilder<> IRB(F.getEntryBlock().getFirstNonPHI());
      VAArgOverflowSize = IRB.CreateLoad(MS.VAArgOverflowSizeTLS);
      Value* CopySize =
          IRB.CreateAdd(ConstantInt::get(MS.IntptrTy, AMD64FpEndOffset),
          VAArgOverflowSize);
      VAArgTLSCopy = IRB.CreateAlloca(Type::getInt8Ty(*MS.C), CopySize);
      IRB.CreateMemCpy(VAArgTLSCopy, MS.VAArgTLS, CopySize, 8);
    }

    // Instrument va_start.
    // Copy va_list shadow from TLS.
    for (size_t i = 0, n = VAStartInstrumentationSet.size(); i < n; i++) {
      CallInst *OrigInst = VAStartInstrumentationSet[i];
      IRBuilder<> IRB(OrigInst->getNextNode());
      Value *VAListTag = OrigInst->getArgOperand(0);

      Value* RegSaveAreaPtrPtr = IRB.CreateIntToPtr(
          IRB.CreateAdd(IRB.CreatePtrToInt(VAListTag, MS.IntptrTy),
                        ConstantInt::get(MS.IntptrTy, 16)),
          Type::getInt64PtrTy(*MS.C));
      Value* RegSaveAreaPtr = IRB.CreateLoad(RegSaveAreaPtrPtr);
      Value* RegSaveAreaShadowPtr =
          getShadowPtr(RegSaveAreaPtr, IRB.getInt8Ty(), IRB);
      IRB.CreateMemCpy(RegSaveAreaShadowPtr, VAArgTLSCopy,
                       AMD64FpEndOffset, 16);

      Value* OverflowArgAreaPtrPtr = IRB.CreateIntToPtr(
          IRB.CreateAdd(IRB.CreatePtrToInt(VAListTag, MS.IntptrTy),
                        ConstantInt::get(MS.IntptrTy, 8)),
          Type::getInt64PtrTy(*MS.C));
      Value* OverflowArgAreaPtr = IRB.CreateLoad(OverflowArgAreaPtrPtr);
      Value* OverflowArgAreaShadowPtr =
          getShadowPtr(OverflowArgAreaPtr, IRB.getInt8Ty(), IRB);
      Value* SrcPtr =
          getShadowPtrForVAArgument(VAArgTLSCopy, IRB, AMD64FpEndOffset);
      IRB.CreateMemCpy(OverflowArgAreaShadowPtr, SrcPtr, VAArgOverflowSize, 16);
    }

    materializeChecks();

    return true;
  }

  // Compute the shadow type that corresponds to a given Value.
  Type *getShadowTy(Value *V) {
    return getShadowTy(V->getType());
  }

  Type *getShadowTy(Type *OrigTy) {
    if (!OrigTy->isSized()) {
      // dbgs() << " notSized() " << *V << "\n";
      return NULL;
    }
    // For integer type, shadow is the same as the original type.
    // This may return weird-sized types like i1.
    if (IntegerType *IT = dyn_cast<IntegerType>(OrigTy))
      return IT;
    if (VectorType *VT = dyn_cast<VectorType>(OrigTy))
      return VectorType::getInteger(VT);
    if (StructType *ST = dyn_cast<StructType>(OrigTy)) {
      SmallVector<Type*, 4> Elements;
      for (unsigned i = 0, n = ST->getNumElements(); i < n; i++)
        Elements.push_back(getShadowTy(ST->getElementType(i)));
      StructType *Res = StructType::get(*MS.C, Elements, ST->isPacked());
      DEBUG(dbgs() << "getShadowTy: " << *ST << " ===> " << *Res << "\n");
      return Res;
    }
    uint32_t TypeSize = MS.TD->getTypeStoreSizeInBits(OrigTy);
    return IntegerType::get(*MS.C, TypeSize);
  }

  LLVM_ATTRIBUTE_NOINLINE
  Type *getShadowTyNoVec(Type *ty) {
    if (VectorType *vt = dyn_cast<VectorType>(ty))
      return IntegerType::get(*MS.C, vt->getBitWidth());
    return ty;
  }

  LLVM_ATTRIBUTE_NOINLINE
  Value *convertToShadowTyNoVec(Value *V, IRBuilder<> &IRB) {
    Type *Ty = V->getType();
    Type *NoVecTy = getShadowTyNoVec(Ty);
    if (Ty == NoVecTy) return V;
    return IRB.CreateBitCast(V, NoVecTy);
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

  // OriginAddr = (ShadowAddr + OriginOffset) & ~3ULL
  //            = Addr & (~ShadowAddr & ~3ULL) + OriginOffset
  Value *getOriginPtr(Value *Addr, IRBuilder<> &IRB) {
    Value *ShadowLong =
        IRB.CreateAnd(IRB.CreatePointerCast(Addr, MS.IntptrTy),
                      ConstantInt::get(MS.IntptrTy, ~MS.ShadowMask & ~3ULL));
    Value *Add =
        IRB.CreateAdd(ShadowLong,
                      ConstantInt::get(MS.IntptrTy, MS.OriginOffset));
    return IRB.CreateIntToPtr(Add, PointerType::get(IRB.getInt32Ty(), 0));
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

  Value *getOriginPtrForArgument(Value *A, IRBuilder<> &IRB,
                                 int ArgOffset) {
    if (!ClTrackOrigins) return NULL;
    Value *Base = IRB.CreatePointerCast(MS.ParamOriginTLS, MS.IntptrTy);
    Base = IRB.CreateAdd(Base, ConstantInt::get(MS.IntptrTy, ArgOffset));
    return IRB.CreateIntToPtr(Base, PointerType::get(MS.OriginTy, 0),
                              "_msarg_o");
  }


  Value *getShadowPtrForVAArgument(Value *A, IRBuilder<> &IRB,
                                    int ArgOffset) {
    Value *Base = IRB.CreatePointerCast(MS.VAArgTLS, MS.IntptrTy);
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

  Value *getOriginPtrForRetval(IRBuilder<> &IRB) {
    // We keep a single origin for the entire retval. Might be too optimistic.
    return MS.RetvalOriginTLS;
  }

  void setShadow(Value *V, Value *SV) {
    assert(ShadowMap[V] == 0);
    ShadowMap[V] = SV;
  }

  void setOrigin(Value *V, Value *Origin) {
    if (!ClTrackOrigins) return;
    assert(OriginMap[V] == 0);
    DEBUG(dbgs() << "ORIGIN: " << *V << "  ==> " << *Origin << "\n");
    OriginMap[V] = Origin;
  }

  // Create a clean (zero) shadow value for a given value.
  Value *getCleanShadow(Value *V) {
    Type *ShadowTy = getShadowTy(V);
    if (!ShadowTy)
      return NULL;
    return  Constant::getNullValue(ShadowTy);
  }

  // We don't have getAllOnesValue for struct types...
  Constant *getPoisonedShadow(Type *ShadowTy) {
    assert(ShadowTy);
    if (isa<IntegerType>(ShadowTy) || isa<VectorType>(ShadowTy))
      return Constant::getAllOnesValue(ShadowTy);
    StructType *ST = cast<StructType>(ShadowTy);
    SmallVector<Constant *, 4> Vals;
    for (unsigned i = 0, n = ST->getNumElements(); i < n; i++)
      Vals.push_back(getPoisonedShadow(ST->getElementType(i)));
    return ConstantStruct::get(ST, Vals);
  }

  // Create a clean (zero) origin.
  Value *getCleanOrigin() {
    return Constant::getNullValue(MS.OriginTy);
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
    if (UndefValue *U = dyn_cast<UndefValue>(V)) {
      Value *AllOnes = getPoisonedShadow(getShadowTy(V));
      DEBUG(dbgs() << "Undef: " << *U << " ==> " << *AllOnes << "\n");
      return AllOnes;
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
        unsigned Size = AI->hasByValAttr()
          ? MS.TD->getTypeAllocSize(AI->getType()->getPointerElementType())
          : MS.TD->getTypeAllocSize(AI->getType());
        if (A == AI) {
          Value *Base = getShadowPtrForArgument(AI, EntryIRB, ArgOffset);
          if (AI->hasByValAttr()) {
            // ByVal pointer itself has clean shadow. We copy the actual
            // argument shadow to the underlying memory.
            Instruction *Cpy = EntryIRB.CreateMemCpy(
                getShadowPtr(V, EntryIRB.getInt8Ty(), EntryIRB),
                Base, Size, AI->getParamAlignment());
            DEBUG(dbgs() << "  ByValCpy: " << *Cpy << "\n");
            *ShadowPtr = getCleanShadow(V);
          } else {
            *ShadowPtr = EntryIRB.CreateLoad(Base);
          }
          DEBUG(dbgs() << "  ARG:    "  << *AI << " ==> " <<
                **ShadowPtr << "\n");
          if (ClTrackOrigins)
            setOrigin(A, EntryIRB.CreateLoad(
                getOriginPtrForArgument(AI, EntryIRB, ArgOffset)));
        }
        ArgOffset += DataLayout::RoundUpAlignment(Size, 8);
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

  Value *getOrigin(Value *V) {
    if (!ClTrackOrigins) return 0;
    if (isa<Instruction>(V) || isa<Argument>(V)) {
      Value *Origin = OriginMap[V];
      if (!Origin) {
        errs() << "NO ORIGIN: " << *V << "\n";
        Origin = getCleanOrigin();
      }
      return Origin;
    }
    return getCleanOrigin();
  }

  Value *getOrigin(Instruction *I, int i) {
    return getOrigin(I->getOperand(i));
  }

  // Remember the place where a check for ShadowVal should be inserted.
  void insertCheck(Value *Val, Instruction *OrigIns) {
    assert(Val);
    if (!InsertChecks) return;
    Instruction *Shadow = dyn_cast_or_null<Instruction>(getShadow(Val));
    if (!Shadow) return;
    Type *ShadowTy = Shadow->getType();
    assert(isa<IntegerType>(ShadowTy) || isa<VectorType>(ShadowTy));
    Instruction *Origin = dyn_cast_or_null<Instruction>(getOrigin(Val));
    InstrumentationSet.push_back(
        ShadowOriginAndInsertPoint(Shadow, Origin, OrigIns));
  }

  //------------------- Visitors.
  LLVM_ATTRIBUTE_NOINLINE
  void visitLoadInst(LoadInst &I) {
    Type *LoadTy = I.getType();
    assert(LoadTy->isSized());
    IRBuilder<> IRB(&I);
    Type *ShadowTy = getShadowTy(&I);
    Value *Addr = I.getPointerOperand();
    Value *ShadowPtr = getShadowPtr(Addr, ShadowTy, IRB);
    setShadow(&I, IRB.CreateAlignedLoad(ShadowPtr, I.getAlignment(), "_msld"));

    if (ClTrapOnDirtyAccess)
      insertCheck(I.getPointerOperand(), &I);

    if (ClTrackOrigins)
      setOrigin(&I, IRB.CreateAlignedLoad(getOriginPtr(Addr, IRB), I.getAlignment()));
  }

  LLVM_ATTRIBUTE_NOINLINE
  void visitStoreInst(StoreInst &I) {
    IRBuilder<> IRB(&I);
    Value *Val = I.getValueOperand();
    Value *Addr = I.getPointerOperand();
    Value *Shadow = getShadow(Val);
    Value *ShadowPtr = getShadowPtr(Addr, Shadow->getType(), IRB);

    StoreInst *NewSI = IRB.CreateAlignedStore(Shadow, ShadowPtr, I.getAlignment());
    DEBUG(dbgs() << "  STORE: " << *NewSI << "\n");
    // If the store is volatile, add a check.
    if (I.isVolatile())
      insertCheck(Val, &I);
    if (ClTrapOnDirtyAccess)
      insertCheck(Addr, &I);

    if (ClTrackOrigins)
      IRB.CreateAlignedStore(getOrigin(Val), getOriginPtr(Addr, IRB), I.getAlignment());
  }

  // Casts.
  void visitSExtInst(SExtInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateSExt(getShadow(&I, 0), I.getType(), "_msprop"));
    setOrigin(&I, getOrigin(&I, 0));
  }

  void visitZExtInst(ZExtInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateZExt(getShadow(&I, 0), I.getType(), "_msprop"));
    setOrigin(&I, getOrigin(&I, 0));
  }

  void visitTruncInst(TruncInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateTrunc(getShadow(&I, 0), I.getType(), "_msprop"));
    setOrigin(&I, getOrigin(&I, 0));
  }

  void visitBitCastInst(BitCastInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateBitCast(getShadow(&I, 0), getShadowTy(&I)));
    setOrigin(&I, getOrigin(&I, 0));
  }

  void visitPtrToIntInst(PtrToIntInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateIntCast(getShadow(&I, 0), getShadowTy(&I), false,
            "_msprop_ptrtoint"));
    setOrigin(&I, getOrigin(&I, 0));
  }

  void visitIntToPtrInst(IntToPtrInst &I) {
    IRBuilder<> IRB(&I);
    setShadow(&I, IRB.CreateIntCast(getShadow(&I, 0), getShadowTy(&I), false,
            "_msprop_inttoptr"));
    setOrigin(&I, getOrigin(&I, 0));
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
    setOriginForNaryOp(I);
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
    setOriginForNaryOp(I);
  }

  LLVM_ATTRIBUTE_NOINLINE
  void setOriginForNaryOp(Instruction &I) {
    if (!ClTrackOrigins) return;
    IRBuilder<> IRB(&I);
    Value *Origin = getOrigin(&I, 0);
    for (unsigned Op = 1, n = I.getNumOperands(); Op < n; ++Op) {
      Value *S = convertToShadowTyNoVec(getShadow(&I, Op - 1), IRB);
      Origin = IRB.CreateSelect(IRB.CreateICmpNE(S, getCleanShadow(S)),
                                Origin, getOrigin(&I, Op));
    }
    setOrigin(&I, Origin);
  }

  // Shadow = Shadow0 | Shadow1, all 3 have the same type.
  void handleShadowOrBinary(Instruction &I) {
    IRBuilder<> IRB(&I);
    Value *Shadow0 = getShadow(&I, 0);
    Value *Shadow1 = getShadow(&I, 1);
    setShadow(&I,  IRB.CreateOr(Shadow0, Shadow1, "_msprop"));
    setOriginForNaryOp(I);
  }

  bool hasStructArgumentOrRetVal(CallInst &I) {
    for (unsigned Op = 0, n = I.getNumArgOperands(); Op < n; ++Op)
      if (I.getArgOperand(Op)->getType()->isStructTy())
        return true;
    if (I.getType()->isStructTy())
      return true;
    return false;
  }

  // Cast between two shadow types, extending or truncating as necessary.
  Value* CreateShadowCast(IRBuilder<>& IRB, Value* V, Type* dstTy) {
    Type* srcTy = V->getType();
    if (dstTy->isIntegerTy() && srcTy->isIntegerTy())
      return IRB.CreateIntCast(V, dstTy, false);
    if (dstTy->isVectorTy() && srcTy->isVectorTy() &&
        dstTy->getVectorNumElements() == srcTy->getVectorNumElements())
      return IRB.CreateIntCast(V, dstTy, false);
    size_t srcSizeInBits = srcTy->isVectorTy() ?
      srcTy->getVectorNumElements() * srcTy->getScalarSizeInBits() :
      srcTy->getPrimitiveSizeInBits();
    size_t dstSizeInBits = dstTy->isVectorTy() ?
      dstTy->getVectorNumElements() * dstTy->getScalarSizeInBits() :
      dstTy->getPrimitiveSizeInBits();
    Value* V1 = IRB.CreateBitCast(V, Type::getIntNTy(*MS.C, srcSizeInBits));
    Value* V2 = IRB.CreateIntCast(V1, Type::getIntNTy(*MS.C, dstSizeInBits), false);
    return IRB.CreateBitCast(V2, dstTy);
    // TODO: handle struct types.
  }

  // Shadow = Shadow0 | ... | ShadowN with proper casting.
  // FIXME: is the casting actually correct?
  // FIXME: merge this with handleShadowOrBinary.
  void handleShadowOr(Instruction &I) {
    IRBuilder<> IRB(&I);
    Value* Shadow = getShadow(&I, 0);
    for (unsigned Op = 1, n = I.getNumOperands(); Op < n; ++Op)
      Shadow = IRB.CreateOr(Shadow,
          CreateShadowCast(IRB, getShadow(&I, Op), Shadow->getType()),
          "_msprop");
    Shadow = CreateShadowCast(IRB, Shadow, getShadowTy(&I));
    setShadow(&I, Shadow);
    setOriginForNaryOp(I);
  }

  void visitFAdd(BinaryOperator &I) { handleShadowOrBinary(I); }
  void visitFSub(BinaryOperator &I) { handleShadowOrBinary(I); }
  void visitFMul(BinaryOperator &I) { handleShadowOrBinary(I); }
  void visitAdd(BinaryOperator &I) { handleShadowOrBinary(I); }
  void visitSub(BinaryOperator &I) { handleShadowOrBinary(I); }
  void visitXor(BinaryOperator &I) { handleShadowOrBinary(I); }
  void visitMul(BinaryOperator &I) { handleShadowOrBinary(I); }

  LLVM_ATTRIBUTE_NOINLINE
  void handleDiv(Instruction &I) {
    IRBuilder<> IRB(&I);
    // Strict on the second argument.
    insertCheck(I.getOperand(1), &I);
    setShadow(&I, getShadow(&I, 0));
    setOrigin(&I, getOrigin(&I, 0));
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
    // * C is fully defined
    // Si = !(C & ~Sc) && Sc
    Value* Zero = Constant::getNullValue(Sc->getType());
    Value* MinusOne = Constant::getAllOnesValue(Sc->getType());
#if 0
    errs() << "Sc:  " << *Sc << "\n";
    errs() << "Sa:  " << *Sa << "\n";
    errs() << "Sb:  " << *Sb << "\n";
    errs() << "Zero:" << *Zero << "\n";
    errs() << "C:   " << *C << "\n";
    errs() << "A:   " << *A << "\n";
    errs() << "B:   " << *B << "\n";
#endif
    Value* Si = IRB.CreateAnd(IRB.CreateICmpNE(Sc, Zero),
        IRB.CreateICmpEQ(IRB.CreateAnd(IRB.CreateXor(Sc, MinusOne), C), Zero));
    Si->setName("_msprop_icmp");
    setShadow(&I, Si);
    setOriginForNaryOp(I);
  }

  void handleSignedRelationalComparison(ICmpInst &I) {
    // Handle (x<0) and (0>=x) comparisons by propagating the highest bit of the
    // shadow.
    Constant *constOp0 = dyn_cast<Constant>(I.getOperand(0));
    Constant *constOp1 = dyn_cast<Constant>(I.getOperand(1));
    Value* op = NULL;
    CmpInst::Predicate pre = I.getPredicate();
    if (constOp0 && constOp0->isNullValue() &&
        (pre == CmpInst::ICMP_SGT || pre == CmpInst::ICMP_SLE)) {
      op = I.getOperand(1);
    } else if (constOp1 && constOp1->isNullValue() &&
        (pre == CmpInst::ICMP_SLT || pre == CmpInst::ICMP_SGE)) {
      op = I.getOperand(0);
    }
    if (op) {
      IRBuilder<> IRB(&I);
      Value* Shadow = IRB.CreateICmpSLT(getShadow(op),
          getCleanShadow(op), "_msprop_icmpslt");
      setShadow(&I, Shadow);
      setOrigin(&I, getOrigin(op));
    } else {
      handleShadowOr(I);
    }
  }

  void visitICmpInst(ICmpInst &I) {
    if (ClHandleICmp && I.isEquality())
      handleEqualityComparison(I);
    else if (ClHandleICmp && I.isSigned() && I.isRelational())
      handleSignedRelationalComparison(I);
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
    setOriginForNaryOp(I);
  }

  void visitShl(BinaryOperator &I) { handleShift(I); }
  void visitAShr(BinaryOperator &I) { handleShift(I); }
  void visitLShr(BinaryOperator &I) { handleShift(I); }

  // At this point we don't know if llvm.memmove will be inlined or not.
  // If we don't instrument it and it gets inlined,
  // our interceptor will not kick in and we will lose the memmove.
  // If we instrument the call here, but it does not get inlined,
  // we will memove the shadow twice: which is bad in case
  // of overlapping regions. So, we simply lower the intrinsic to a call.
  void handleMemMove(MemMoveInst &I) {
    IRBuilder<> IRB(&I);
    IRB.CreateCall3(MS.MemmoveFn,
        IRB.CreatePointerCast(I.getArgOperand(0), IRB.getInt8PtrTy()),
        IRB.CreatePointerCast(I.getArgOperand(1), IRB.getInt8PtrTy()),
        IRB.CreateIntCast(I.getArgOperand(2), MS.IntptrTy, false));
    I.eraseFromParent();
  }

  // Similar to memmove: avoid copying shadow twice.
  // This is somewhat unfortunate as it may slowdown small constant memcpys.
  // FIXME: consider doing manual inline for small constant sizes and proper
  // alignment.
  void handleMemCpy(MemCpyInst &I) {
    IRBuilder<> IRB(&I);
    IRB.CreateCall3(MS.MemcpyFn,
        IRB.CreatePointerCast(I.getArgOperand(0), IRB.getInt8PtrTy()),
        IRB.CreatePointerCast(I.getArgOperand(1), IRB.getInt8PtrTy()),
        IRB.CreateIntCast(I.getArgOperand(2), MS.IntptrTy, false));
    I.eraseFromParent();
  }

  // Same as memcpy.
  void handleMemSet(MemSetInst &I) {
    IRBuilder<> IRB(&I);
    IRB.CreateCall3(MS.MemsetFn,
        IRB.CreatePointerCast(I.getArgOperand(0), IRB.getInt8PtrTy()),
        IRB.CreateIntCast(I.getArgOperand(1), IRB.getInt32Ty(), false),
        IRB.CreateIntCast(I.getArgOperand(2), MS.IntptrTy, false));
    I.eraseFromParent();
  }

  void handleVAStart(IntrinsicInst &I) {
    IRBuilder<> IRB(&I);
    VAStartInstrumentationSet.push_back(&I);
    Value *VAListTag = I.getArgOperand(0);
    Value *ShadowPtr = getShadowPtr(VAListTag, IRB.getInt8Ty(), IRB);

    // Unpoison the whole __va_list_tag.
    // FIXME: magic ABI constants.
    IRB.CreateMemSet(ShadowPtr, Constant::getNullValue(IRB.getInt8Ty()),
        /* size */24, /* alignment */16, false);
  }

  void handleVACopy(IntrinsicInst &I) {
    IRBuilder<> IRB(&I);
    Value *VAListTag = I.getArgOperand(0);
    Value *ShadowPtr = getShadowPtr(VAListTag, IRB.getInt8Ty(), IRB);

    // Unpoison the whole __va_list_tag.
    // FIXME: magic ABI constants.
    IRB.CreateMemSet(ShadowPtr, Constant::getNullValue(IRB.getInt8Ty()),
        /* size */ 24, /* alignment */ 16, false);
  }

  enum ArgClass { ARG_GP, ARG_FP, ARG_MEMORY };

  ArgClass classifyArgument(Value* arg) {
    // A very rough approximation of X86_64 argument classification rules.
    Type* T = arg->getType();
    if (T->isFPOrFPVectorTy() || T->isX86_MMXTy())
      return ARG_FP;
    if (T->isIntegerTy() && T->getPrimitiveSizeInBits() <= 64)
      return ARG_GP;
    if (T->isPointerTy())
      return ARG_GP;
    return ARG_MEMORY;
  }

  // GET_INTRINSIC_MODREF_BEHAVIOR requires that ModRefBehaviour definition is
  // in scope.
  struct Dummy : public AliasAnalysis {
    static ModRefBehavior getIntrinsicModRefBehaviour(Intrinsic::ID iid) {
#define GET_INTRINSIC_MODREF_BEHAVIOR
#include "llvm/Intrinsics.gen"
#undef GET_INTRINSIC_MODREF_BEHAVIOR
    }
  };

  void handleUnknownIntrinsic(IntrinsicInst &I) {
    // TODO: handle struct types in CreateShadowCast
    if (hasStructArgumentOrRetVal(I)) {
      visitInstruction(I);
      return;
    }

    if (I.getNumArgOperands() == 0) {
      visitInstruction(I);
      return;
    }

    Intrinsic::ID iid = I.getIntrinsicID();
    AliasAnalysis::ModRefBehavior modref =
      Dummy::getIntrinsicModRefBehaviour(iid);
    bool readsMemory =
      (modref == AliasAnalysis::OnlyReadsArgumentPointees ||
          modref == AliasAnalysis::OnlyReadsMemory);
    bool writesMemory =
      (modref == AliasAnalysis::OnlyAccessesArgumentPointees ||
          modref == AliasAnalysis::UnknownModRefBehavior);
    assert(!(readsMemory && writesMemory));

    // See if we need to propagate shadow at all.
    if (!writesMemory && I.getType()->isVoidTy()) {
      visitInstruction(I);
      return;
    }

    int pointerOpIdx = -1;
    Type* MemAccessType = NULL;
    for (unsigned i = 0, n = I.getNumArgOperands(); i < n; ++i) {
      Value* Op = I.getArgOperand(i);
      if (Op->getType()->isPointerTy()) {
        if (pointerOpIdx < 0) {
          pointerOpIdx = i;
        } else {
          // Two pointer operands? Meh.
          visitInstruction(I);
          return;
        }
      } else if (!MemAccessType) {
        MemAccessType = Op->getType();
      }
    }

    if (pointerOpIdx < 0 && (readsMemory || writesMemory)) {
      // No idea how to handle this.
      visitInstruction(I);
      return;
    }

    if (!MemAccessType)
      MemAccessType = I.getType();

    if (MemAccessType->isVoidTy()) {
      // Can't figure out memory access size.
      visitInstruction(I);
      return;
    }

    Type* MemAccessShadowTy = getShadowTy(MemAccessType);

    DEBUG(dbgs() << (readsMemory ? "read" : (writesMemory ? "write" :
           "nomem")) << " intrinsic: " << I << "\n");
    DEBUG(dbgs() << "pointer argument: " << pointerOpIdx << "\n");
    DEBUG(dbgs() << "memory access type: " << *MemAccessType << "\n");
    DEBUG(dbgs() << "shadow type: " << *MemAccessShadowTy << "\n");

    IRBuilder<> IRB(&I);

    // Calculate OR'ed shadow of all scalar (or vector of scalars) arguments.
    Value* Shadow = NULL;
    Value* Origin = NULL;
    for (int i = 0, n = I.getNumArgOperands(); i < n; ++i) {
      // For nomem intrinsics, we mix in the shadow of the pointer argument,
      // as well.
      if (i == pointerOpIdx && (readsMemory || writesMemory)) continue;
      Value* Op = I.getArgOperand(i);
      Value* OpShadow = CreateShadowCast(IRB, getShadow(Op), MemAccessShadowTy);
      if (!Shadow)
        Shadow = OpShadow;
      else
        Shadow = IRB.CreateOr(Shadow, OpShadow, "_msprop");
      if (ClTrackOrigins) {
        Value* OpOrigin = getOrigin(Op);
        if (!Origin) {
          Origin = OpOrigin;
        } else {
          assert(!Shadow);
          Value *S = convertToShadowTyNoVec(Shadow, IRB);
          Origin = IRB.CreateSelect(IRB.CreateICmpNE(S, getCleanShadow(S)),
              Origin, OpOrigin);
        }
      }
    }

    // Read shadow by the pointer argument and mix it in.
    if (pointerOpIdx >= 0 && readsMemory) {
      Value *Op = I.getArgOperand(pointerOpIdx);
      Value *ShadowPtr = getShadowPtr(Op, MemAccessShadowTy, IRB);
      // FIXME: do we know anything at all about this load alignment?
      // The same goes for the store below.
      Value* OpShadow = IRB.CreateAlignedLoad(ShadowPtr, 1, "_msld");
      if (!Shadow)
        Shadow = OpShadow;
      else
        Shadow = IRB.CreateOr(Shadow, OpShadow, "_msprop");
      if (ClTrackOrigins) {
        Value* MemOrigin = IRB.CreateAlignedLoad(getOriginPtr(Op, IRB), 1);
        if (!Origin) {
          Origin = MemOrigin;
        } else {
          assert(!Shadow);
          Value *S = convertToShadowTyNoVec(Shadow, IRB);
          Origin = IRB.CreateSelect(IRB.CreateICmpNE(S, getCleanShadow(S)),
              Origin, MemOrigin);
        }
      }
    }

    assert(Shadow);
    if (ClTrackOrigins) assert(Origin);

    // Store shadow by the pointer argument.
    if (pointerOpIdx >= 0 && writesMemory) {
      Value *Op = I.getArgOperand(pointerOpIdx);
      Value *ShadowPtr = getShadowPtr(Op, MemAccessShadowTy, IRB);
      IRB.CreateAlignedStore(Shadow, ShadowPtr, 1);
      if (ClTrackOrigins)
        IRB.CreateAlignedStore(Origin, getOriginPtr(Op, IRB), 1);
    }

    if (!I.getType()->isVoidTy()) {
      Shadow = CreateShadowCast(IRB, Shadow, getShadowTy(&I));
      setShadow(&I, Shadow);
      if (ClTrackOrigins)
        setOrigin(&I, Origin);
    }
  }

  void handleIntrinsicInst(IntrinsicInst &I) {
    switch (I.getIntrinsicID()) {
    case llvm::Intrinsic::memset:
      handleMemSet(*dyn_cast<MemSetInst>(&I)); break;
    case llvm::Intrinsic::memcpy:
      handleMemCpy(*dyn_cast<MemCpyInst>(&I)); break;
    case llvm::Intrinsic::memmove:
      handleMemMove(*dyn_cast<MemMoveInst>(&I)); break;
    case llvm::Intrinsic::vastart:
      handleVAStart(I); break;
    case llvm::Intrinsic::vacopy:
      handleVACopy(I); break;
    default:
      handleUnknownIntrinsic(I);
    }
  }

  void visitCallSite(CallSite CS) {
    Instruction &I = *CS.getInstruction();
    assert(CS.isCall() || CS.isInvoke());
    if (CS.isCall()) {
      // Allow only tail calls with the same types, otherwise
      // we may have a false positive: shadow for a non-void RetVal
      // will get propagated to a void RetVal.
      CallInst *Call = cast<CallInst>(&I);
      if (Call->isTailCall() && Call->getType() != Call->getParent()->getType())
        Call->setTailCall(false);
      if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(&I)) {
        handleIntrinsicInst(*II);
        return;
      }
    }
    IRBuilder<> IRB(&I);
    unsigned ArgOffset = 0;
    DEBUG(dbgs() << "  CallSite: " << I << "\n");
    for (CallSite::arg_iterator ArgIt = CS.arg_begin(), End = CS.arg_end();
         ArgIt != End; ++ArgIt) {
      Value *A = *ArgIt;
      unsigned i = ArgIt - CS.arg_begin();
      if (!A->getType()->isSized()) {
        DEBUG(dbgs() << "Arg " << i << " is not sized: " << I << "\n");
        continue;
      }
      unsigned Size = 0;
      Value *Store = 0;
      // Compute the Shadow for arg even if it is ByVal, because
      // in that case getShadow() will copy the actual arg shadow to
      // __msan_param_tls.
      Value *ArgShadow = getShadow(A);
      Value *ArgShadowBase = getShadowPtrForArgument(A, IRB, ArgOffset);
      DEBUG(dbgs() << "  Arg#" << i << ": " << *A <<
            " Shadow: " << *ArgShadow << "\n");
      if (CS.paramHasAttr(i + 1, Attributes::ByVal)) {
        assert(A->getType()->isPointerTy());
        Size = MS.TD->getTypeAllocSize(A->getType()->getPointerElementType());
        unsigned Alignment = CS.getParamAlignment(i + 1);
        Store = IRB.CreateMemCpy(ArgShadowBase,
                                 getShadowPtr(A, Type::getInt8Ty(*MS.C), IRB),
                                 Size, Alignment);
      } else {
        Size = MS.TD->getTypeAllocSize(A->getType());
        Store = IRB.CreateStore(ArgShadow, ArgShadowBase);
      }
      if (ClTrackOrigins)
        IRB.CreateStore(getOrigin(A),
                        getOriginPtrForArgument(A, IRB, ArgOffset));
      assert(Size != 0 && Store != 0);
      DEBUG(dbgs() << "  Param:" << *Store << "\n");
      ArgOffset += DataLayout::RoundUpAlignment(Size, 8);
    }
    DEBUG(dbgs() << "  done with call args\n");
    // For VarArg functions, store the argument shadow in an ABI-specific format
    // that corresponds to va_list layout.
    // We do this because Clang lowers va_arg in the frontend, and this pass
    // only sees the low level code that deals with va_list internals.
    // A much easier alternative (provided that Clang emits va_arg instructions)
    // would have been to associate each live instance of va_list with a copy of
    // MSanParamTLS, and extract shadow on va_arg() call in the argument list
    // order.
    FunctionType *FT = cast<FunctionType>(CS.getCalledValue()->getType()->
        getContainedType(0));
    if (FT->isVarArg()) {
      unsigned GpOffset = 0;
      unsigned FpOffset = AMD64GpEndOffset;
      unsigned OverflowOffset = AMD64FpEndOffset;
      for (CallSite::arg_iterator ArgIt = CS.arg_begin(), End = CS.arg_end();
           ArgIt != End; ++ArgIt) {
        Value *A = *ArgIt;
        ArgClass arg_class = classifyArgument(A);
        if (arg_class == ARG_GP && GpOffset >= AMD64GpEndOffset)
          arg_class = ARG_MEMORY;
        if (arg_class == ARG_FP && FpOffset >= AMD64FpEndOffset)
          arg_class = ARG_MEMORY;
        Value* Base;
        switch (arg_class) {
        case ARG_GP:
          Base = getShadowPtrForVAArgument(A, IRB, GpOffset);
          GpOffset += 8;
          break;
        case ARG_FP:
          Base = getShadowPtrForVAArgument(A, IRB, FpOffset);
          FpOffset += 16;
          break;
        case ARG_MEMORY:
          Base = getShadowPtrForVAArgument(A, IRB, OverflowOffset);
          OverflowOffset += DataLayout::RoundUpAlignment(
              MS.TD->getTypeAllocSize(A->getType()), 8);
        }
        IRB.CreateStore(getShadow(A), Base);
      }
      IRB.CreateStore(ConstantInt::get(MS.VAArgOverflowSizeTLS->getType()->
              getElementType(), OverflowOffset - AMD64FpEndOffset),
          MS.VAArgOverflowSizeTLS);
    }
    // Now, get the shadow for the RetVal.
    if (!I.getType()->isSized()) return;
    IRBuilder<> IRBBefore(&I);
    // Untill we have full dynamic coverage, make sure the retval shadow is 0.
    Value *Base = getShadowPtrForRetval(&I, IRBBefore);
    IRBBefore.CreateStore(getCleanShadow(&I), Base);
    Instruction *NextInsn = 0;
    if (CS.isCall()) {
      NextInsn = I.getNextNode();
    } else {
      BasicBlock *NormalDest = cast<InvokeInst>(&I)->getNormalDest();
      if (!NormalDest->getSinglePredecessor()) {
        // FIXME: this case is tricky, so we are just conservative here.
        // Perhaps we need to split the edge between this BB and NormalDest,
        // but a naive attempt to use SplitEdge leads to a crash.
        setShadow(&I, getCleanShadow(&I));
        setOrigin(&I, getCleanOrigin());
        return;
      }
      NextInsn = NormalDest->getFirstInsertionPt();
      assert(NextInsn);
    }
    IRBuilder<> IRBAfter(NextInsn);
    setShadow(&I, IRBAfter.CreateLoad(getShadowPtrForRetval(&I, IRBAfter),
                                      "_msret"));
    if (ClTrackOrigins)
      setOrigin(&I, IRBAfter.CreateLoad(getOriginPtrForRetval(IRBAfter)));
  }

  void visitReturnInst(ReturnInst &I) {
    IRBuilder<> IRB(&I);
    if (Value *RetVal = I.getReturnValue()) {
      // Set the shadow for the RetVal.
      Value *Shadow = getShadow(RetVal);
      Value *ShadowPtr = getShadowPtrForRetval(RetVal, IRB);
      DEBUG(dbgs() << "Return: " << *Shadow << "\n" << *ShadowPtr << "\n");
      IRB.CreateStore(Shadow, ShadowPtr);
      if (ClTrackOrigins)
        IRB.CreateStore(getOrigin(RetVal), getOriginPtrForRetval(IRB));
    }
  }

  void visitPHINode(PHINode &I) {
    IRBuilder<> IRB(&I);
    ShadowPHINodes.push_back(&I);
    setShadow(&I, IRB.CreatePHI(getShadowTy(&I), I.getNumIncomingValues(),
                                "_msphi_s"));
    if (ClTrackOrigins)
      setOrigin(&I, IRB.CreatePHI(MS.OriginTy, I.getNumIncomingValues(),
                                  "_msphi_o"));
  }

  void visitAllocaInst(AllocaInst &I) {
    setShadow(&I, getCleanShadow(&I));
    if (!ClPoisonStack) return;
    IRBuilder<> IRB(I.getNextNode());
    uint64_t Size = MS.TD->getTypeAllocSize(I.getAllocatedType());
    if (ClPoisonStackWithCall) {
      IRB.CreateCall2(MS.MsanPoisonStackFn,
                      IRB.CreatePointerCast(&I, IRB.getInt8PtrTy()),
                      ConstantInt::get(MS.IntptrTy, Size));
    } else {
      Value *ShadowBase = getShadowPtr(&I, Type::getInt8PtrTy(*MS.C), IRB);
      IRB.CreateMemSet(ShadowBase, IRB.getInt8(ClPoisonStackPattern),
                       Size, I.getAlignment());
    }

    if (ClTrackOrigins) {
      setOrigin(&I, getCleanOrigin());
      SmallString<2048> StackDescriptionStorage;
      raw_svector_ostream StackDescription(StackDescriptionStorage);
      // We create a string with a description of the stack allocation and
      // pass it into __msan_set_alloca_origin.
      // It will be printed by the run-time if stack-originated UMR us found.
      // The first 4 bytes of the string are set to '----' and will be replaced
      // by __msan_va_arg_overflow_size_tls at the first call.
      StackDescription << "----" << I.getName() << "@" << F.getName();
      Value *Descr =
          createPrivateNonConstGlobalForString(*F.getParent(),
                                               StackDescription.str());
      IRB.CreateCall3(MS.MsanSetAllocaOriginFn,
                      IRB.CreatePointerCast(&I, IRB.getInt8PtrTy()),
                      ConstantInt::get(MS.IntptrTy, Size),
                      IRB.CreatePointerCast(Descr, IRB.getInt8PtrTy()));
    }
  }

  void visitSelectInst(SelectInst& I) {
    IRBuilder<> IRB(&I);
    setShadow(&I,  IRB.CreateSelect(I.getCondition(),
            getShadow(I.getTrueValue()), getShadow(I.getFalseValue()),
            "_msprop"));
    if (ClTrackOrigins)
      setOrigin(&I, IRB.CreateSelect(I.getCondition(),
            getOrigin(I.getTrueValue()), getOrigin(I.getFalseValue())));
  }

  void visitLandingPadInst(LandingPadInst &I) {
    // Do nothing.
    // See http://code.google.com/p/memory-sanitizer/issues/detail?id=1
    setShadow(&I, getCleanShadow(&I));
    setOrigin(&I, getCleanOrigin());
  }

  void visitGetElementPtrInst(GetElementPtrInst &I) {
    handleShadowOr(I);
  }

  void visitExtractValueInst(ExtractValueInst &I) {
    IRBuilder<> IRB(&I);
    Value *Agg = I.getAggregateOperand();
    DEBUG(dbgs() << "ExtractValue:  " << I << "\n");
    Value *AggShadow = getShadow(Agg);
    DEBUG(dbgs() << "   AggShadow:  " << *AggShadow << "\n");
    Value *ResShadow = IRB.CreateExtractValue(AggShadow, I.getIndices());
    DEBUG(dbgs() << "   ResShadow:  " << *ResShadow << "\n");
    setShadow(&I, ResShadow);
    setOrigin(&I, getCleanOrigin());
  }

  void visitInsertValueInst(InsertValueInst &I) {
    IRBuilder<> IRB(&I);
    DEBUG(dbgs() << "InsertValue:  " << I << "\n");
    Value *AggShadow = getShadow(I.getAggregateOperand());
    Value *InsShadow = getShadow(I.getInsertedValueOperand());
    DEBUG(dbgs() << "   AggShadow:  " << *AggShadow << "\n");
    DEBUG(dbgs() << "   InsShadow:  " << *InsShadow << "\n");
    Value *Res = IRB.CreateInsertValue(AggShadow, InsShadow, I.getIndices());
    DEBUG(dbgs() << "   Res:        " << *Res << "\n");
    setShadow(&I, Res);
    setOrigin(&I, getCleanOrigin());
  }

  void dumpInst(Instruction &I) {
    if (CallInst* CI = dyn_cast<CallInst>(&I)) {
      errs() << "ZZZ call " << CI->getCalledFunction()->getName() << "\n";
    } else {
      errs() << "ZZZ " << I.getOpcodeName() << "\n";
    }
    errs() << "QQQ " << I << "\n";
  }

  LLVM_ATTRIBUTE_NOINLINE
  void visitResumeInst(ResumeInst &I) {
    DEBUG(dbgs() << "Resume: " << I << "\n");
    // Nothing to do here.
  }

  LLVM_ATTRIBUTE_NOINLINE
  void visitInstruction(Instruction &I) {
    // Everything else: stop propagating and check for poisoned shadow.
    if (ClDumpStrictInstructions)
      dumpInst(I);
    DEBUG(dbgs() << "DEFAULT: " << I << "\n");
    for (size_t i = 0, n = I.getNumOperands(); i < n; i++)
      insertCheck(I.getOperand(i), &I);
    setShadow(&I, getCleanShadow(&I));
    setOrigin(&I, getCleanOrigin());
  }
};

}  // namespace

bool MemorySanitizer::runOnFunction(Function &F) {
  MemorySanitizerVisitor Visitor(F, *this);

  // Clear out readonly/readnone attributes.
  AttrBuilder B;
  B.addAttribute(Attributes::ReadOnly)
    .addAttribute(Attributes::ReadNone);
  F.removeAttribute(AttrListPtr::FunctionIndex,
      Attributes::get(F.getContext(), B));

  return Visitor.runOnFunction();
}
