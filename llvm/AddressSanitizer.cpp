//===-- AddressSanitizer.cpp - memory error detector ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
// Details of the algorithm:
//  http://code.google.com/p/address-sanitizer/wiki/AddressSanitizerAlgorithm
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "asan"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/OwningPtr.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Function.h"
#include "llvm/InlineAsm.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/system_error.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Type.h"

#include <string>
#include <algorithm>

using namespace llvm;

static const uint64_t kDefaultShadowScale = 3;
static const uint64_t kDefaultShadowOffset32 = 1ULL << 29;
static const uint64_t kDefaultShadowOffset64 = 1ULL << 44;

static const size_t kMaxStackMallocSize = 1 << 16;  // 64K
static const uintptr_t kFrameNameMagic = 0x41B58AB3;

static const char *kAsanModuleCtorName = "asan.module_ctor";
static const char *kAsanReportErrorTemplate = "__asan_report_";
static const char *kAsanRegisterGlobalName = "__asan_register_global";
static const char *kAsanInitName = "__asan_init";
static const char *kAsanMappingOffsetName = "__asan_mapping_offset";
static const char *kAsanMappingScaleName = "__asan_mapping_scale";
static const char *kAsanStackMallocName = "__asan_stack_malloc";
static const char *kAsanStackFreeName = "__asan_stack_free";

static const char *kLLVMGlobalCtors = "llvm.global_ctors";

static const int kAsanStackLeftRedzoneMagic = 0xf1;
static const int kAsanStackMidRedzoneMagic = 0xf2;
static const int kAsanStackRightRedzoneMagic = 0xf3;
static const int kAsanStackPartialRedzoneMagic = 0xf4;

// Command-line flags.

// (potentially) user-visible flags.
static cl::opt<bool> ClAsan("asan",
       cl::desc("enable AddressSanitizer"), cl::init(false));
static cl::opt<bool> ClInstrumentReads("asan-instrument-reads",
       cl::desc("instrument read instructions"), cl::init(true));
static cl::opt<bool> ClInstrumentWrites("asan-instrument-writes",
       cl::desc("instrument write instructions"), cl::init(true));
static cl::opt<bool> ClStack("asan-stack",
       cl::desc("Handle stack memory"), cl::init(true));
static cl::opt<bool> ClUseAfterReturn("asan-use-after-return",
       cl::desc("Check return-after-free"), cl::init(false));
static cl::opt<bool> ClGlobals("asan-globals",
       cl::desc("Handle global objects"), cl::init(true));
static cl::opt<bool> ClMemIntrin("asan-memintrin",
       cl::desc("Handle memset/memcpy/memmove"), cl::init(true));
static cl::opt<std::string>  ClBlackListFile("asan-blacklist",
       cl::desc("File containing the list of functions to ignore "
                "during instrumentation"));
static cl::opt<bool> ClUseCall("asan-use-call",
       cl::desc("Use function call to generate a crash"), cl::init(true));

// These flags *will* allow to change the shadow mapping. Not usable yet.
// The shadow mapping looks like
//    Shadow = (Mem >> scale) + (1 << offset_log)
static cl::opt<int> ClMappingScale("asan-mapping-scale",
       cl::desc("scale of asan shadow mapping"), cl::init(0));
static cl::opt<int> ClMappingOffsetLog("asan-mapping-offset-log",
       cl::desc("offset of asan shadow mapping"), cl::init(-1));

// Optimization flags. Not user visible, used mostly for testing
// and benchmarking the tool.
static cl::opt<bool> ClOpt("asan-opt",
       cl::desc("Optimize instrumentation"), cl::init(true));
static cl::opt<bool> ClOptSameTemp("asan-opt-same-temp",
       cl::desc("Instrument the same temp just once"), cl::init(true));
static cl::opt<bool> ClOptGlobals("asan-opt-globals",
       cl::desc("Don't instrument scalar globals"), cl::init(true));

// Debug flags.
static cl::opt<int> ClDebug("asan-debug", cl::desc("debug"), cl::init(0));
static cl::opt<int> ClDebugStack("asan-debug-stack", cl::desc("debug stack"),
                                 cl::init(0));
static cl::opt<std::string> ClDebugFunc("asan-debug-func",
                                        cl::desc("Debug func"));
static cl::opt<int> ClDebugMin("asan-debug-min",
                               cl::desc("Debug min inst"), cl::init(-1));
static cl::opt<int> ClDebugMax("asan-debug-max",
                               cl::desc("Debug man inst"), cl::init(-1));

namespace {

// Blacklisted functions are not instrumented.
// The blacklist file contains one or more lines like this:
// ---
// fun:FunctionWildCard
// ---
// This is similar to the "ignore" feature of ThreadSanitizer.
// http://code.google.com/p/data-race-test/wiki/ThreadSanitizerIgnores
class BlackList {
 public:
  BlackList(const std::string &Path);
  bool isIn(const Function &F);
 private:
  Regex *Functions;
};

/// AddressSanitizer: instrument the code in module to find memory bugs.
struct AddressSanitizer : public ModulePass {
  AddressSanitizer();
  void instrumentMop(Instruction *I);
  void instrumentAddress(Instruction *OrigIns, IRBuilder<> &IRB,
                         Value *Addr, uint32_t TypeSize, bool IsWrite);
  Instruction *generateCrashCode(IRBuilder<> &IRB, Value *Addr,
                                 bool IsWrite, uint32_t TypeSize);
  bool instrumentMemIntrinsic(MemIntrinsic *MI);
  void instrumentMemIntrinsicParam(Instruction *OrigIns, Value *Addr,
                                  Value *Size,
                                   Instruction *InsertBefore, bool IsWrite);
  Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
  bool handleFunction(Module &M, Function &F);
  bool poisonStackInFunction(Module &M, Function &F);
  virtual bool runOnModule(Module &M);
  bool insertGlobalRedzones(Module &M);
  BranchInst *splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *Cmp);
  static char ID;  // Pass identification, replacement for typeid

 private:

  uint64_t getAllocaSizeInBytes(AllocaInst *AI) {
    Type *Ty = AI->getAllocatedType();
    uint64_t SizeInBytes = TD->getTypeStoreSizeInBits(Ty) / 8;
    return SizeInBytes;
  }
  uint64_t getAlignedSize(uint64_t SizeInBytes) {
    return ((SizeInBytes + RedzoneSize - 1)
            / RedzoneSize) * RedzoneSize;
  }
  uint64_t getAlignedAllocaSize(AllocaInst *AI) {
    uint64_t SizeInBytes = getAllocaSizeInBytes(AI);
    return getAlignedSize(SizeInBytes);
  }

  void PoisonStack(const ArrayRef<AllocaInst*> &AllocaVec, IRBuilder<> IRB,
                   Value *ShadowBase, bool DoPoison);

  Module      *CurrentModule;
  LLVMContext *C;
  TargetData *TD;
  uint64_t MappingOffset;
  int MappingScale;
  size_t RedzoneSize;
  int LongSize;
  Type *IntptrTy;
  Type *IntptrPtrTy;
  Function *AsanCtorFunction;
  Function *AsanInitFunction;
  Instruction *CtorInsertBefore;
  OwningPtr<BlackList> BL;
};
}  // namespace

char AddressSanitizer::ID = 0;
INITIALIZE_PASS(AddressSanitizer, "asan",
    "AddressSanitizer: detects use-after-free and out-of-bounds bugs.",
    false, false)
AddressSanitizer::AddressSanitizer() : ModulePass(ID) { }
ModulePass *llvm::createAddressSanitizerPass() {
  return new AddressSanitizer();
}

// Create a constant for Str so that we can pass it to the run-time lib.
static GlobalVariable *createPrivateGlobalForString(Module &M, StringRef Str) {
  Constant *StrConst = ConstantArray::get(M.getContext(), Str);
  return new GlobalVariable(M, StrConst->getType(), true,
                            GlobalValue::PrivateLinkage, StrConst, "");
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
BranchInst *AddressSanitizer::splitBlockAndInsertIfThen(
    Instruction *SplitBefore, Value *Cmp) {
  BasicBlock *Head = SplitBefore->getParent();
  BasicBlock *Tail = Head->splitBasicBlock(SplitBefore);
  TerminatorInst *HeadOldTerm = Head->getTerminator();
  BasicBlock *NewBasicBlock =
      BasicBlock::Create(*C, "", Head->getParent());
  BranchInst *HeadNewTerm = BranchInst::Create(/*ifTrue*/NewBasicBlock,
                                               /*ifFalse*/Tail,
                                               Cmp);
  ReplaceInstWithInst(HeadOldTerm, HeadNewTerm);

  BranchInst *CheckTerm = BranchInst::Create(Tail, NewBasicBlock);
  return CheckTerm;
}

Value *AddressSanitizer::memToShadow(Value *Shadow, IRBuilder<> &IRB) {
  // Shadow >> scale
  Shadow = IRB.CreateLShr(Shadow, MappingScale);
  if (MappingOffset == 0)
    return Shadow;
  // (Shadow >> scale) | offset
  return IRB.CreateOr(Shadow, ConstantInt::get(IntptrTy,
                                               MappingOffset));
}

void AddressSanitizer::instrumentMemIntrinsicParam(Instruction *OrigIns,
    Value *Addr, Value *Size, Instruction *InsertBefore, bool IsWrite) {
  // Check the first byte.
  {
    IRBuilder<> IRB(InsertBefore);
    instrumentAddress(OrigIns, IRB, Addr, 8, IsWrite);
  }
  // Check the last byte.
  {
    IRBuilder<> IRB(InsertBefore);
    Value *SizeMinusOne = IRB.CreateSub(
        Size, ConstantInt::get(Size->getType(), 1));
    SizeMinusOne = IRB.CreateIntCast(SizeMinusOne, IntptrTy, false);
    Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
    Value *AddrPlusSizeMinisOne = IRB.CreateAdd(AddrLong, SizeMinusOne);
    instrumentAddress(OrigIns, IRB, AddrPlusSizeMinisOne, 8, IsWrite);
  }
}

// Instrument memset/memmove/memcpy
bool AddressSanitizer::instrumentMemIntrinsic(MemIntrinsic *MI) {
  Value *Dst = MI->getDest();
  MemTransferInst *MemTran = dyn_cast<MemTransferInst>(MI);
  Value *Src = MemTran ? MemTran->getSource() : NULL;
  Value *Length = MI->getLength();

  Constant *ConstLength = dyn_cast<Constant>(Length);
  Instruction *InsertBefore = MI;
  if (ConstLength) {
    if (ConstLength->isNullValue()) return false;
  } else {
    // The size is not a constant so it could be zero -- check at run-time.
    IRBuilder<> IRB(InsertBefore);

    Value *Cmp = IRB.CreateICmpNE(Length,
                                   Constant::getNullValue(Length->getType()));
    InsertBefore = splitBlockAndInsertIfThen(InsertBefore, Cmp);
  }

  instrumentMemIntrinsicParam(MI, Dst, Length, InsertBefore, true);
  if (Src)
    instrumentMemIntrinsicParam(MI, Src, Length, InsertBefore, false);
  return true;
}

static Value *getLDSTOperand(Instruction *I) {
  if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
    return LI->getPointerOperand();
  }
  return cast<StoreInst>(*I).getPointerOperand();
}

void AddressSanitizer::instrumentMop(Instruction *I) {
  int IsWrite = isa<StoreInst>(*I);
  Value *Addr = getLDSTOperand(I);
  if (ClOpt && ClOptGlobals && isa<GlobalVariable>(Addr)) {
    // We are accessing a global scalar variable. Nothing to catch here.
    return;
  }
  Type *OrigPtrTy = Addr->getType();
  Type *OrigTy = cast<PointerType>(OrigPtrTy)->getElementType();

  assert(OrigTy->isSized());
  uint32_t TypeSize = TD->getTypeStoreSizeInBits(OrigTy);

  if (TypeSize != 8  && TypeSize != 16 &&
      TypeSize != 32 && TypeSize != 64 && TypeSize != 128) {
    // Ignore all unusual sizes.
    return;
  }

  IRBuilder<> IRB(I);
  instrumentAddress(I, IRB, Addr, TypeSize, IsWrite);
}

Instruction *AddressSanitizer::generateCrashCode(
    IRBuilder<> &IRB, Value *Addr, bool IsWrite, uint32_t TypeSize) {

  if (ClUseCall) {
    // Here we use a call instead of arch-specific asm to report an error.
    // This is almost always slower (because the codegen needs to generate
    // prologue/epilogue for otherwise leaf functions) and generates more code.
    // This mode could be useful if we can not use SIGILL for some reason.
    //
    // IsWrite and TypeSize are encoded in the function name.
    std::string FunctionName = std::string(kAsanReportErrorTemplate) +
        (IsWrite ? "store" : "load") + itostr(TypeSize / 8);
    Value *ReportWarningFunc = CurrentModule->getOrInsertFunction(
        FunctionName, IRB.getVoidTy(), IntptrTy, NULL);
    CallInst *Call = IRB.CreateCall(ReportWarningFunc, Addr);
    Call->setDoesNotReturn();
    return Call;
  }

  uint32_t LogOfSizeInBytes = CountTrailingZeros_32(TypeSize / 8);
  assert(8U * (1 << LogOfSizeInBytes) == TypeSize);
  uint8_t TelltaleValue = IsWrite * 8 + LogOfSizeInBytes;
  assert(TelltaleValue < 16);

  // Move the failing address to %rax/%eax
  FunctionType *Fn1Ty = FunctionType::get(
      IRB.getVoidTy(), ArrayRef<Type*>(IntptrTy), false);
  const char *MovStr = LongSize == 32
      ? "mov $0, %eax" : "mov $0, %rax";
  Value *AsmMov = InlineAsm::get(
      Fn1Ty, StringRef(MovStr), StringRef("r"), true);
  IRB.CreateCall(AsmMov, Addr);

  // crash with ud2; could use int3, but it is less friendly to gdb.
  // after ud2 put a 1-byte instruction that encodes the access type and size.

  const char *TelltaleInsns[16] = {
    "push   %eax",  // 0x50
    "push   %ecx",  // 0x51
    "push   %edx",  // 0x52
    "push   %ebx",  // 0x53
    "push   %esp",  // 0x54
    "push   %ebp",  // 0x55
    "push   %esi",  // 0x56
    "push   %edi",  // 0x57
    "pop    %eax",  // 0x58
    "pop    %ecx",  // 0x59
    "pop    %edx",  // 0x5a
    "pop    %ebx",  // 0x5b
    "pop    %esp",  // 0x5c
    "pop    %ebp",  // 0x5d
    "pop    %esi",  // 0x5e
    "pop    %edi"   // 0x5f
  };

  std::string AsmStr = "ud2;";
  AsmStr += TelltaleInsns[TelltaleValue];
  Value *MyAsm = InlineAsm::get(FunctionType::get(Type::getVoidTy(*C), false),
                                StringRef(AsmStr), StringRef(""), true);
  CallInst *AsmCall = IRB.CreateCall(MyAsm);

  // This saves us one jump, but triggers a bug in RA (or somewhere else):
  // while building 483.xalancbmk the compiler goes into infinite loop in
  // llvm::SpillPlacement::iterate() / RAGreedy::growRegion
  // AsmCall->setDoesNotReturn();
  return AsmCall;
}

void AddressSanitizer::instrumentAddress(Instruction *OrigIns,
                                         IRBuilder<> &IRB, Value *Addr,
                                         uint32_t TypeSize, bool IsWrite) {
  Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);

  Type *ShadowTy  = IntegerType::get(
      *C, std::max(8U, TypeSize >> MappingScale));
  Type *ShadowPtrTy = PointerType::get(ShadowTy, 0);
  Value *ShadowPtr = memToShadow(AddrLong, IRB);
  Value *CmpVal = Constant::getNullValue(ShadowTy);
  Value *ShadowValue = IRB.CreateLoad(
      IRB.CreateIntToPtr(ShadowPtr, ShadowPtrTy));

  Value *Cmp = IRB.CreateICmpNE(ShadowValue, CmpVal);

  Instruction *CheckTerm = splitBlockAndInsertIfThen(
      cast<Instruction>(Cmp)->getNextNode(), Cmp);
  IRBuilder<> IRB2(CheckTerm);

  size_t Granularity = 1 << MappingScale;
  if (TypeSize < 8 * Granularity) {
    // Addr & (Granularity - 1)
    Value *Lower3Bits = IRB2.CreateAnd(
        AddrLong, ConstantInt::get(IntptrTy, Granularity - 1));
    // (Addr & (Granularity - 1)) + size - 1
    Value *LastAccessedByte = IRB2.CreateAdd(
        Lower3Bits, ConstantInt::get(IntptrTy, TypeSize / 8 - 1));
    // (uint8_t) ((Addr & (Granularity-1)) + size - 1)
    LastAccessedByte = IRB2.CreateIntCast(
        LastAccessedByte, IRB.getInt8Ty(), false);
    // ((uint8_t) ((Addr & (Granularity-1)) + size - 1)) >= ShadowValue
    Value *Cmp2 = IRB2.CreateICmpSGE(LastAccessedByte, ShadowValue);

    CheckTerm = splitBlockAndInsertIfThen(CheckTerm, Cmp2);
  }

  IRBuilder<> IRB1(CheckTerm);
  Instruction *Crash = generateCrashCode(IRB1, AddrLong, IsWrite, TypeSize);
  Crash->setDebugLoc(OrigIns->getDebugLoc());
}

// Append F to the list of global ctors with the given Priority.
// TODO: move to llvm/lib/Transforms/Utils.
static void appendToGlobalCtors(Module &M, Function *F,
                                int Priority) {
  IRBuilder<> IRB(M.getContext());
  FunctionType *FnTy = FunctionType::get(IRB.getVoidTy(), false);
  StructType *Ty = StructType::get(
      IRB.getInt32Ty(), PointerType::getUnqual(FnTy), NULL);

  Constant *RuntimeCtorInit = ConstantStruct::get(
      Ty, IRB.getInt32(Priority), F, NULL);

  // Get the current set of static global constructors and add the new ctor
  // to the list.
  SmallVector<Constant *, 16> CurrentCtors;
  GlobalVariable * GVCtor = M.getNamedGlobal(kLLVMGlobalCtors);
  if (GVCtor) {
    if (Constant *Const = GVCtor->getInitializer()) {
      for (uint32_t index = 0, num = Const->getNumOperands();
           index < num; ++index) {
        CurrentCtors.push_back(cast<Constant>(Const->getOperand(index)));
      }
    }
    // Rename the global variable so that we can name our global
    // kLLVMGlobalCtors
    GVCtor->setName("removed");
    GVCtor->eraseFromParent();
  }

  CurrentCtors.push_back(RuntimeCtorInit);

  // Create a new initializer.
  ArrayType *AT = ArrayType::get(RuntimeCtorInit->getType(),
                                 CurrentCtors.size());
  Constant *NewInit = ConstantArray::get(AT, CurrentCtors);

  // Create the new kLLVMGlobalCtors global variable and replace all uses of
  // the old global variable with the new one.
  new GlobalVariable(M,
                     NewInit->getType(),
                     false,
                     GlobalValue::AppendingLinkage,
                     NewInit,
                     kLLVMGlobalCtors);
}

// This function replaces all global variables with new variables that have
// trailing redzones. It also creates a function that poisons
// redzones and inserts this function into kLLVMGlobalCtors.
bool AddressSanitizer::insertGlobalRedzones(Module &M) {
  SmallVector<GlobalVariable *, 16> GlobalsToChange;

  for (Module::GlobalListType::iterator G = M.getGlobalList().begin(),
       E = M.getGlobalList().end(); G != E; ++G) {
    Type *Ty = cast<PointerType>(G->getType())->getElementType();
    DEBUG(dbgs() << "GLOBAL: " << *G);

    if (!Ty->isSized()) continue;
    if (!G->hasInitializer()) continue;
    if (G->getLinkage() != GlobalVariable::ExternalLinkage &&
        G->getLinkage() != GlobalVariable::CommonLinkage  &&
        G->getLinkage() != GlobalVariable::PrivateLinkage  &&
        G->getLinkage() != GlobalVariable::InternalLinkage
        ) {
      // do we care about other linkages?
      continue;
    }
    // For now, just ignore this Alloca if the alignment is large.
    if (G->getAlignment() > RedzoneSize) continue;

    // Ignore all the globals with the names starting with "\01L_OBJC_".
    // Many of those are put into the .cstring section. The linker compresses
    // that section by removing the spare \0s after the string terminator, so
    // our redzones get broken.
    if ((G->getName().find("\01L_OBJC_") == 0) ||
        (G->getName().find("\01l_OBJC_") == 0)) {
      DEBUG(dbgs() << "Ignoring \\01L_OBJC_* global: " << *G);
      continue;
    }

    // Ignore the globals from the __OBJC section. The ObjC runtime assumes
    // those conform to /usr/lib/objc/runtime.h, so we can't add redzones to
    // them.
    if (G->hasSection()) {
      StringRef Section(G->getSection());
      if ((Section.find("__OBJC,") == 0) ||
          (Section.find("__DATA, __objc_") == 0)) {
         DEBUG(dbgs() << "Ignoring ObjC runtime global: " << *G);
         continue;
      }
    }


    GlobalsToChange.push_back(G);
  }

  if (GlobalsToChange.empty())
    return false;

  IRBuilder<> IRB(CtorInsertBefore);

  for (size_t i = 0, n = GlobalsToChange.size(); i < n; i++) {
    GlobalVariable *G = GlobalsToChange[i];
    PointerType *PtrTy = cast<PointerType>(G->getType());
    Type *Ty = PtrTy->getElementType();
    uint64_t SizeInBytes = TD->getTypeStoreSizeInBits(Ty) / 8;
    uint64_t right_redzone_size = RedzoneSize +
        (RedzoneSize - (SizeInBytes % RedzoneSize));
    Type *RightRedZoneTy = ArrayType::get(IRB.getInt8Ty(), right_redzone_size);

    StructType *new_ty = StructType::get(
        Ty, RightRedZoneTy, NULL);
    Constant *new_initializer = ConstantStruct::get(
        new_ty,
        G->getInitializer(),
        Constant::getNullValue(RightRedZoneTy),
        NULL);

    GlobalVariable *orig_name_glob =
        createPrivateGlobalForString(M, G->getName());

    // Create a new global variable with enough space for a redzone.
    GlobalVariable *new_global = new GlobalVariable(
        M, new_ty, G->isConstant(), G->getLinkage(),
        new_initializer,
        "",
        G, G->isThreadLocal());
    new_global->copyAttributesFrom(G);
    new_global->setAlignment(RedzoneSize);

    Constant *Indices[2];
    Indices[0] = IRB.getInt32(0);
    Indices[1] = IRB.getInt32(0);

    G->replaceAllUsesWith(
        ConstantExpr::getGetElementPtr(new_global, Indices, 2));
    new_global->takeName(G);
    G->eraseFromParent();

    Value *asan_register_global = M.getOrInsertFunction(
        kAsanRegisterGlobalName, IRB.getVoidTy(),
        IntptrTy, IntptrTy, IntptrTy, NULL);
    cast<Function>(asan_register_global)->setLinkage(
        Function::ExternalLinkage);

    IRB.CreateCall3(asan_register_global,
                    IRB.CreatePointerCast(new_global, IntptrTy),
                    ConstantInt::get(IntptrTy, SizeInBytes),
                    IRB.CreatePointerCast(orig_name_glob, IntptrTy));

    DEBUG(dbgs() << "NEW GLOBAL:\n" << *new_global);
  }

  DEBUG(dbgs() << M);

  return true;
}

// virtual
bool AddressSanitizer::runOnModule(Module &M) {
  if (!ClAsan) return false;
  // Initialize the private fields. No one has accessed them before.
  TD = getAnalysisIfAvailable<TargetData>();
  if (!TD)
    return false;
  BL.reset(new BlackList(ClBlackListFile));

  CurrentModule = &M;
  C = &(M.getContext());
  LongSize = TD->getPointerSizeInBits();
  IntptrTy = Type::getIntNTy(*C, LongSize);
  IntptrPtrTy = PointerType::get(IntptrTy, 0);

  AsanCtorFunction = Function::Create(
      FunctionType::get(Type::getVoidTy(*C), false),
      GlobalValue::InternalLinkage, kAsanModuleCtorName, &M);
  BasicBlock *AsanCtorBB = BasicBlock::Create(*C, "", AsanCtorFunction);
  CtorInsertBefore = ReturnInst::Create(*C, AsanCtorBB);

  // call __asan_init in the module ctor.
  IRBuilder<> IRB(CtorInsertBefore);
  AsanInitFunction = cast<Function>(
      M.getOrInsertFunction(kAsanInitName, IRB.getVoidTy(), NULL));
  AsanInitFunction->setLinkage(Function::ExternalLinkage);
  IRB.CreateCall(AsanInitFunction);

  MappingOffset = LongSize == 32
      ? kDefaultShadowOffset32 : kDefaultShadowOffset64;
  if (ClMappingOffsetLog >= 0) {
    if (ClMappingOffsetLog == 0) {
      // special case
      MappingOffset = 0;
    } else {
      MappingOffset = 1ULL << ClMappingOffsetLog;
    }
  }
  MappingScale = kDefaultShadowScale;
  if (ClMappingScale) {
    MappingScale = ClMappingScale;
  }
  // Redzone used for stack and globals is at least 32 bytes.
  // For scales 6 and 7, the redzone has to be 64 and 128 bytes respectively.
  RedzoneSize = std::max(32, (int)(1 << MappingScale));
  GlobalValue *asan_mapping_offset =
      new GlobalVariable(M, IntptrTy, true, GlobalValue::LinkOnceODRLinkage,
                     ConstantInt::get(IntptrTy, MappingOffset),
                     kAsanMappingOffsetName);
  GlobalValue *asan_mapping_scale =
      new GlobalVariable(M, IntptrTy, true, GlobalValue::LinkOnceODRLinkage,
                         ConstantInt::get(IntptrTy, MappingScale),
                         kAsanMappingScaleName);

  // Read these globals, otherwise they may be optimized away.
  IRB.CreateLoad(asan_mapping_scale, true);
  IRB.CreateLoad(asan_mapping_offset, true);

  bool Res = false;

  if (ClGlobals)
    Res |= insertGlobalRedzones(M);

  for (Module::iterator F = M.begin(), E = M.end(); F != E; ++F) {
    if (F->isDeclaration()) continue;
    Res |= handleFunction(M, *F);
  }

  appendToGlobalCtors(M, AsanCtorFunction, 1 /*high priority*/);

  return Res;
}

bool AddressSanitizer::handleFunction(Module &M, Function &F) {
  if (BL->isIn(F)) return false;
  if (&F == AsanCtorFunction) return false;

  if (!ClDebugFunc.empty() && ClDebugFunc != F.getNameStr())
    return false;
  // We want to instrument every address only once per basic block
  // (unless there are calls between uses).
  SmallSet<Value*, 16> TempsToInstrument;
  SmallVector<Instruction*, 16> ToInstrument;

  // Fill the set of memory operations to instrument.
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    TempsToInstrument.clear();
    for (BasicBlock::iterator BI = FI->begin(), BE = FI->end();
         BI != BE; ++BI) {
      if ((isa<LoadInst>(BI) && ClInstrumentReads) ||
          (isa<StoreInst>(BI) && ClInstrumentWrites)) {
        Value *Addr = getLDSTOperand(BI);
        if (ClOpt && ClOptSameTemp) {
          if (!TempsToInstrument.insert(Addr))
            continue;  // We've seen this temp in the current BB.
        }
      } else if (isa<MemIntrinsic>(BI) && ClMemIntrin) {
        // ok, take it.
      } else {
        if (isa<CallInst>(BI)) {
          // A call inside BB.
          TempsToInstrument.clear();
        }
        continue;
      }
      ToInstrument.push_back(BI);
    }
  }

  // Instrument.
  int NumInstrumented = 0;
  for (size_t i = 0, n = ToInstrument.size(); i != n; i++) {
    Instruction *Inst = ToInstrument[i];
    if (ClDebugMin < 0 || ClDebugMax < 0 ||
        (NumInstrumented >= ClDebugMin && NumInstrumented <= ClDebugMax)) {
      if (isa<StoreInst>(Inst) || isa<LoadInst>(Inst))
        instrumentMop(Inst);
      else
        instrumentMemIntrinsic(cast<MemIntrinsic>(Inst));
    }
    NumInstrumented++;
  }

  DEBUG(dbgs() << F);

  bool ChangedStack = poisonStackInFunction(M, F);

  // For each NSObject descendant having a +load method, this method is invoked
  // by the ObjC runtime before any of the static constructors is called.
  // Therefore we need to instrument such methods with a call to __asan_init
  // at the beginning in order to initialize our runtime before any access to
  // the shadow memory.
  // We cannot just ignore these methods, because they may call other
  // instrumented functions.
  if (F.getNameStr().find(" load]") != std::string::npos) {
    IRBuilder<> IRB(F.begin()->begin());
    IRB.CreateCall(AsanInitFunction);
  }

  return NumInstrumented > 0 || ChangedStack;
}

static uint64_t ValueForPoison(uint64_t PoisonByte, size_t ShadowRedzoneSize) {
  if (ShadowRedzoneSize == 1) return PoisonByte;
  if (ShadowRedzoneSize == 2) return (PoisonByte << 8) + PoisonByte;
  if (ShadowRedzoneSize == 4)
    return (PoisonByte << 24) + (PoisonByte << 16) +
        (PoisonByte << 8) + (PoisonByte);
  assert(0 && "ShadowRedzoneSize is either 1, 2 or 4");
  return 0;
}

static void PoisonShadowPartialRightRedzone(uint8_t *Shadow,
                                            size_t Size,
                                            size_t RedzoneSize,
                                            size_t ShadowGranularity,
                                            uint8_t Magic) {
  for (size_t i = 0; i < RedzoneSize;
       i+= ShadowGranularity, Shadow++) {
    if (i + ShadowGranularity <= Size) {
      *Shadow = 0;  // fully addressable
    } else if (i >= Size) {
      *Shadow = Magic;  // unaddressable
    } else {
      *Shadow = Size - i;  // first Size-i bytes are addressable
    }
  }
}

void AddressSanitizer::PoisonStack(const ArrayRef<AllocaInst*> &AllocaVec,
                                   IRBuilder<> IRB,
                                   Value *ShadowBase, bool DoPoison) {
  size_t ShadowRZSize = RedzoneSize >> MappingScale;
  assert(ShadowRZSize >= 1 && ShadowRZSize <= 4);
  Type *RZTy = Type::getIntNTy(*C, ShadowRZSize * 8);
  Type *RZPtrTy = PointerType::get(RZTy, 0);

  Value *PoisonLeft  = ConstantInt::get(RZTy,
    ValueForPoison(DoPoison ? kAsanStackLeftRedzoneMagic : 0LL, ShadowRZSize));
  Value *PoisonMid   = ConstantInt::get(RZTy,
    ValueForPoison(DoPoison ? kAsanStackMidRedzoneMagic : 0LL, ShadowRZSize));
  Value *PoisonRight = ConstantInt::get(RZTy,
    ValueForPoison(DoPoison ? kAsanStackRightRedzoneMagic : 0LL, ShadowRZSize));

  // poison the first red zone.
  IRB.CreateStore(PoisonLeft, IRB.CreateIntToPtr(ShadowBase, RZPtrTy));

  // poison all other red zones.
  uint64_t Pos = RedzoneSize;
  for (size_t i = 0, n = AllocaVec.size(); i < n; i++) {
    AllocaInst *AI = AllocaVec[i];
    uint64_t SizeInBytes = getAllocaSizeInBytes(AI);
    uint64_t AlignedSize = getAlignedAllocaSize(AI);
    assert(AlignedSize - SizeInBytes < RedzoneSize);
    Value *Ptr = NULL;

    Pos += AlignedSize;

    assert(ShadowBase->getType() == IntptrTy);
    if (SizeInBytes < AlignedSize) {
      // Poison the partial redzone at right
      Ptr = IRB.CreateAdd(
          ShadowBase, ConstantInt::get(IntptrTy,
                                       (Pos >> MappingScale) - ShadowRZSize));
      size_t AddressableBytes = RedzoneSize - (AlignedSize - SizeInBytes);
      uint32_t Poison = 0;
      if (DoPoison) {
        PoisonShadowPartialRightRedzone((uint8_t*)&Poison, AddressableBytes,
                                        RedzoneSize,
                                        1ULL << MappingScale,
                                        kAsanStackPartialRedzoneMagic);
      }
      Value *PartialPoison = ConstantInt::get(RZTy, Poison);
      IRB.CreateStore(PartialPoison, IRB.CreateIntToPtr(Ptr, RZPtrTy));
    }

    // Poison the full redzone at right.
    Ptr = IRB.CreateAdd(ShadowBase,
                        ConstantInt::get(IntptrTy, Pos >> MappingScale));
    Value *Poison = i == AllocaVec.size() - 1 ? PoisonRight : PoisonMid;
    IRB.CreateStore(Poison, IRB.CreateIntToPtr(Ptr, RZPtrTy));

    Pos += RedzoneSize;
  }
}

// Find all static Alloca instructions and put
// poisoned red zones around all of them.
// Then unpoison everything back before the function returns.
//
// Stack poisoning does not play well with exception handling.
// When an exception is thrown, we essentially bypass the code
// that unpoisones the stack. This is why the run-time library has
// to intercept __cxa_throw (as well as longjmp, etc) and unpoison the entire
// stack in the interceptor. This however does not work inside the
// actual function which catches the exception. Most likely because the
// compiler hoists the load of the shadow value somewhere too high.
// This causes asan to report a non-existing bug on 453.povray.
// It sounds like an LLVM bug.
bool AddressSanitizer::poisonStackInFunction(Module &M, Function &F) {
  if (!ClStack) return false;
  SmallVector<AllocaInst*, 16> AllocaVec;
  SmallVector<Instruction*, 8> RetVec;
  uint64_t TotalSize = 0;

  // Filter out Alloca instructions we want (and can) handle.
  // Collect Ret instructions.
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    BasicBlock &BB = *FI;
    for (BasicBlock::iterator BI = BB.begin(), BE = BB.end();
         BI != BE; ++BI) {
      if (isa<ReturnInst>(BI)) {
          RetVec.push_back(BI);
          continue;
      }

      AllocaInst *AI = dyn_cast<AllocaInst>(BI);
      if (!AI) continue;
      if (AI->isArrayAllocation()) continue;
      if (!AI->isStaticAlloca()) continue;
      if (!AI->getAllocatedType()->isSized()) continue;
      if (AI->getAlignment() > RedzoneSize) continue;
      AllocaVec.push_back(AI);
      uint64_t AlignedSize =  getAlignedAllocaSize(AI);
      TotalSize += AlignedSize;
    }
  }

  if (AllocaVec.empty()) return false;

  uint64_t LocalStackSize = TotalSize + (AllocaVec.size() + 1) * RedzoneSize;

  bool DoStackMalloc = ClUseAfterReturn
      && LocalStackSize <= kMaxStackMallocSize;

  Instruction *InsBefore = AllocaVec[0];
  IRBuilder<> IRB(InsBefore);


  Type *ByteArrayTy = ArrayType::get(IRB.getInt8Ty(), LocalStackSize);
  AllocaInst *MyAlloca =
      new AllocaInst(ByteArrayTy, "MyAlloca", InsBefore);
  MyAlloca->setAlignment(RedzoneSize);
  assert(MyAlloca->isStaticAlloca());
  Value *OrigStackBase = IRB.CreatePointerCast(MyAlloca, IntptrTy);
  Value *LocalStackBase = OrigStackBase;

  if (DoStackMalloc) {
    Value *AsanStackMallocFunc = M.getOrInsertFunction(
        kAsanStackMallocName, IntptrTy, IntptrTy, IntptrTy, NULL);
    LocalStackBase = IRB.CreateCall2(AsanStackMallocFunc,
        ConstantInt::get(IntptrTy, LocalStackSize), OrigStackBase);
  }

  // This string will be parsed by the run-time (DescribeStackAddress).
  SmallString<2048> StackDescriptionStorage;
  raw_svector_ostream StackDescription(StackDescriptionStorage);
  StackDescription << F.getName() << " " << AllocaVec.size() << " ";

  uint64_t Pos = RedzoneSize;
  // Replace Alloca instructions with base+offset.
  for (size_t i = 0, n = AllocaVec.size(); i < n; i++) {
    AllocaInst *AI = AllocaVec[i];
    uint64_t SizeInBytes = getAllocaSizeInBytes(AI);
    StringRef Name = AI->getName();
    StackDescription << Pos << " " << SizeInBytes << " "
                     << Name.size() << " " << Name << " ";
    uint64_t AlignedSize = getAlignedAllocaSize(AI);
    assert((AlignedSize % RedzoneSize) == 0);
    AI->replaceAllUsesWith(
        IRB.CreateIntToPtr(
            IRB.CreateAdd(LocalStackBase, ConstantInt::get(IntptrTy, Pos)),
            AI->getType()));
    Pos += AlignedSize + RedzoneSize;
  }
  assert(Pos == LocalStackSize);

  // Write the Magic value and the frame description constant to the redzone.
  Value *BasePlus0 = IRB.CreateIntToPtr(LocalStackBase, IntptrPtrTy);
  IRB.CreateStore(ConstantInt::get(IntptrTy, kFrameNameMagic), BasePlus0);
  Value *BasePlus1 = IRB.CreateAdd(LocalStackBase,
                                   ConstantInt::get(IntptrTy, LongSize/8));
  BasePlus1 = IRB.CreateIntToPtr(BasePlus1, IntptrPtrTy);
  Value *Description = IRB.CreatePointerCast(
      createPrivateGlobalForString(M, StackDescription.str()),
      IntptrTy);
  IRB.CreateStore(Description, BasePlus1);

  // Poison the stack redzones at the entry.
  Value *ShadowBase = memToShadow(LocalStackBase, IRB);
  PoisonStack(ArrayRef<AllocaInst*>(AllocaVec), IRB, ShadowBase, true);

  Value *AsanStackFreeFunc = NULL;
  if (DoStackMalloc) {
    AsanStackFreeFunc = M.getOrInsertFunction(
        kAsanStackFreeName, IRB.getVoidTy(),
        IntptrTy, IntptrTy, IntptrTy, NULL);
  }

  // Unpoison the stack before all ret instructions.
  for (size_t i = 0, n = RetVec.size(); i < n; i++) {
    Instruction *Ret = RetVec[i];
    IRBuilder<> IRBRet(Ret);

    if (DoStackMalloc) {
      IRBRet.CreateCall3(AsanStackFreeFunc, LocalStackBase,
                         ConstantInt::get(IntptrTy, LocalStackSize),
                         OrigStackBase);
    } else {
      PoisonStack(ArrayRef<AllocaInst*>(AllocaVec), IRBRet, ShadowBase, false);
      // Overwrite kFrameNameMagic with something else.
      // Otherwise, we may report an error incorrectly if we access
      // an uninitialized stack out of bounds.
      IRBRet.CreateStore(ConstantInt::get(IntptrTy, 0), BasePlus0);
    }
  }

  if (ClDebugStack) {
    DEBUG(dbgs() << F);
  }

  return true;
}

BlackList::BlackList(const std::string &Path) {
  Functions = NULL;
  const char *kFunPrefix = "fun:";
  if (!ClBlackListFile.size()) return;
  std::string Fun;

  OwningPtr<MemoryBuffer> File;
  if (error_code EC = MemoryBuffer::getFile(ClBlackListFile.c_str(), File)) {
    errs() << EC.message();
    exit(1);
  }
  MemoryBuffer *Buff = File.take();
  const char *Data = Buff->getBufferStart();
  size_t DataLen = Buff->getBufferSize();
  SmallVector<StringRef, 16> Lines;
  SplitString(StringRef(Data, DataLen), Lines, "\n\r");
  for (size_t i = 0, numLines = Lines.size(); i < numLines; i++) {
    if (Lines[i].startswith(kFunPrefix)) {
      std::string ThisFunc = Lines[i].substr(strlen(kFunPrefix));
      if (Fun.size()) {
        Fun += "|";
      }
      // add ThisFunc replacing * with .*
      for (size_t j = 0, n = ThisFunc.size(); j < n; j++) {
        if (ThisFunc[j] == '*')
          Fun += '.';
        Fun += ThisFunc[j];
      }
    }
  }
  if (Fun.size()) {
    Functions = new Regex(Fun);
  }
}

bool BlackList::isIn(const Function &F) {
  if (Functions) {
    bool Res = Functions->match(F.getNameStr());
    return Res;
  }
  return false;
}
