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
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/CallingConv.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/GlobalAlias.h"
#include "llvm/InlineAsm.h"
#include "llvm/InstrTypes.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/MathExtras.h"
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
#include <vector>
#include <algorithm>

using std::vector;
using std::max;

using namespace llvm;

static const uint64_t kDefaultShadowScale = 3;
static const uint64_t kDefaultShadowOffset32 = 29;
static const uint64_t kDefaultShadowOffset64 = 44;

static const size_t kMaxStackMallocSize = 1 << 16;  // 64K

static const char *kAsanModuleCtorName = "asan.module_ctor";
static const char *kAsanReportErrorTemplate = "__asan_report_error_%d";
static const char *kAsanRedzoneNameSuffix = "_asanRZ";
static const char *kAsanRegisterGlobalName = "__asan_register_global";
static const char *kAsanInitName = "__asan_init";
static const char *kAsanMappingOffsetName = "__asan_mapping_offset";
static const char *kAsanMappingScaleName = "__asan_mapping_scale";
static const char *kAsanStackMallocName = "__asan_stack_malloc";
static const char *kAsanStackFreeName = "__asan_stack_free";

static const char *kLLVMGlobalCtors = "llvm.global_ctors";

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
#ifndef __APPLE__
       cl::desc("Handle global objects"), cl::init(true));
#else
       // TODO(glider): fix -asan-globals on Mac OS.
       cl::desc("-asan-globals is not supported on Mac yet"), cl::init(false));
#endif
static cl::opt<bool> ClMemIntrin("asan-memintrin",
       cl::desc("Handle memset/memcpy/memmove"), cl::init(true));
static cl::opt<std::string>  ClBlackListFile("asan-blacklist",
       cl::desc("File containing the list of functions to ignore "
                        "during instrumentation"));
static cl::opt<bool> ClUseCall("asan-use-call",
       cl::desc("Use function call to generate a crash"), cl::init(false));

// These flags *will* allow to change the shadow mapping. Not usable yet.
// The shadow mapping looks like
//    Shadow = (Mem >> scale) + (1 << offset_log)
static cl::opt<int> ClMappingScale("asan-mapping-scale",
       cl::desc("scale of asan shadow mapping"), cl::init(0));
static cl::opt<int> ClMappingOffsetLog("asan-mapping-offset-log",
       cl::desc("offset of asan shadow mapping"), cl::init(0));

// Optimization flags. Not user visible, used mostly for testing
// and benchmarking the tool.
static cl::opt<bool> ClOpt("asan-opt",
       cl::desc("Optimize instrumentation"), cl::init(true));
static cl::opt<bool> ClOptSameTemp("asan-opt-same-temp",
       cl::desc("Instrument the same temp just once"), cl::init(true));
static cl::opt<bool> ClOptGlobals("asan-opt-globals",
       cl::desc("Don't instrument scalar globals"), cl::init(true));


static cl::opt<bool> ClExperimental("asan-experiment",
       cl::desc("Experimental flag"), cl::init(false));

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
  bool IsIn(const Function &F);
 private:
  Regex *Functions;
};

struct AddressSanitizer : public ModulePass {
  AddressSanitizer();
  void instrumentMop(Instruction *Ins);
  void instrumentAddress(Instruction *OrigIns, IRBuilder<> &IRB,
                         Value *Addr, uint32_t TypeSize, bool IsWrite);
  Instruction *generateCrashCode(IRBuilder<> &IRB, Value *Addr,
                                 int TelltaleValue);
  bool instrumentMemIntrinsic(MemIntrinsic *MI);
  void instrumentMemIntrinsicParam(Instruction *OrigIns, Value *Addr,
                                  Value *Size,
                                   Instruction *InsertBefore, bool IsWrite);
  Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
  bool handleFunction(Module &M, Function &F);
  bool poisonStackInFunction(Module &M, Function &F);
  virtual bool runOnModule(Module &M);
  bool insertGlobalRedzones(Module &M);
  void appendToGlobalCtors(Module &M, Function *F);
  BranchInst *splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *Cmp);
  static char ID;  // Pass identification, replacement for typeid

 private:

  uint64_t getAllocaSizeInBytes(AllocaInst *AI) {
    Type *ty = AI->getAllocatedType();
    uint64_t SizeInBytes = TD->getTypeStoreSizeInBits(ty) / 8;
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
  uint64_t MappingOffsetLog;
  int MappingScale;
  size_t RedzoneSize;
  int LongSize;
  Type *VoidTy;
  Type *LongTy;
  Type *LongPtrTy;
  Type *i32Ty;
  Type *i32PtrTy;
  Type *ByteTy;
  Type *BytePtrTy;
  FunctionType *Fn0Ty;
  Instruction *CtorInsertBefore;
  BlackList *BL;
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

static void CloneDebugInfo(Instruction *From, Instruction *To) {
  To->setDebugLoc(From->getDebugLoc());
}

Value *AddressSanitizer::memToShadow(Value *Shadow, IRBuilder<> &IRB) {
  // Shadow >> scale
  Shadow = IRB.CreateLShr(Shadow, MappingScale);
  // (Shadow >> scale) | offset
  return IRB.CreateOr(Shadow, ConstantInt::get(LongTy,
                                               1ULL << MappingOffsetLog));
}

void AddressSanitizer::instrumentMemIntrinsicParam(Instruction *OrigIns,
    Value *Addr, Value *Size, Instruction *InsertBefore, bool IsWrite) {
  // Check the first byte.
  {
    IRBuilder<> IRB(InsertBefore->getParent(), InsertBefore);
    instrumentAddress(OrigIns, IRB, Addr, 8, IsWrite);
  }
  // Check the last byte.
  {
    IRBuilder<> IRB(InsertBefore->getParent(), InsertBefore);
    Value *SizeMinusOne = IRB.CreateSub(
        Size, ConstantInt::get(Size->getType(), 1));
    SizeMinusOne = IRB.CreateIntCast(SizeMinusOne, LongTy, false);
    Value *AddrLong = IRB.CreatePointerCast(Addr, LongTy);
    Value *AddrPlusSizeMinisOne = IRB.CreateAdd(AddrLong, SizeMinusOne);
    instrumentAddress(OrigIns, IRB, AddrPlusSizeMinisOne, 8, IsWrite);
  }
}

// Instrument memset/memmove/memcpy
bool AddressSanitizer::instrumentMemIntrinsic(MemIntrinsic *MI) {
  Value *dst = MI->getDest();
  MemTransferInst *mtran = dyn_cast<MemTransferInst>(MI);
  Value *src = mtran ? mtran->getSource() : NULL;
  Value *length = MI->getLength();

  Constant *ConstLength = dyn_cast<Constant>(length);
  Instruction *InsertBefore = MI->getNextNode();
  if (ConstLength) {
    if (ConstLength->isNullValue()) return false;
  } else {
    // The size is not a constant so it could be zero -- check at run-time.
    IRBuilder<> IRB(InsertBefore->getParent(), InsertBefore);

    Value *Cmp = IRB.CreateICmpNE(length,
                                   Constant::getNullValue(length->getType()));
    BranchInst *term = splitBlockAndInsertIfThen(InsertBefore, Cmp);
    InsertBefore = term;
  }

  instrumentMemIntrinsicParam(MI, dst, length, InsertBefore, true);
  if (src)
    instrumentMemIntrinsicParam(MI, src, length, InsertBefore, false);
  return true;
}

static Value *getLDSTOperand(Instruction *inst) {
  if (LoadInst *ld = dyn_cast<LoadInst>(inst)) {
    return ld->getPointerOperand();
  }
  return cast<StoreInst>(*inst).getPointerOperand();
}

void AddressSanitizer::instrumentMop(Instruction *Ins) {
  int IsWrite = isa<StoreInst>(*Ins);
  Value *Addr = getLDSTOperand(Ins);
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
    // TODO(kcc): do something better.
    return;
  }

  IRBuilder<> IRB(Ins->getParent(), Ins);
  instrumentAddress(Ins, IRB, Addr, TypeSize, IsWrite);
}

Instruction *AddressSanitizer::generateCrashCode(
    IRBuilder<> &IRB, Value *Addr, int TelltaleValue) {
  if (ClUseCall) {
    // Here we use a call instead of arch-specific asm to report an error.
    // This is almost always slower (because the codegen needs to generate
    // prologue/epilogue for otherwise leaf functions) and generates more code.
    // This mode could be useful if we can not use SIGILL for some reason.
    //
    // The TelltaleValue (is_write and size) is encoded in the function name.
    std::string FunctionName = kAsanReportErrorTemplate + itostr(TelltaleValue);
    Value *ReportWarningFunc = CurrentModule->getOrInsertFunction(
        FunctionName, VoidTy, LongTy, NULL);
    CallInst *call = IRB.CreateCall(ReportWarningFunc, Addr);
    return call;
  }

  // Move the failing address to %rax/%eax
  FunctionType *Fn1Ty = FunctionType::get(
      VoidTy, ArrayRef<Type*>(LongTy), false);
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
  Value *MyAsm = InlineAsm::get(Fn0Ty, StringRef(AsmStr),
                                StringRef(""), true);
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
  unsigned LogOfSizeInBytes = CountTrailingZeros_32(TypeSize / 8);
  assert(8U * (1 << LogOfSizeInBytes) == TypeSize);
  uint8_t TelltaleValue = IsWrite * 8 + LogOfSizeInBytes;
  assert(TelltaleValue < 16);

  Value *AddrLong = IRB.CreatePointerCast(Addr, LongTy);

  Type *ShadowTy  = IntegerType::get(
      *C, max(8U, TypeSize >> MappingScale));
  Type *ShadowPtrTy = PointerType::get(ShadowTy, 0);
  Value *ShadowPtr = memToShadow(AddrLong, IRB);
  Value *CmpVal = Constant::getNullValue(ShadowTy);
  Value *ShadowValue = IRB.CreateLoad(
      IRB.CreateIntToPtr(ShadowPtr, ShadowPtrTy));

  if (ClExperimental) {
    // Experimental code.
    Value *Lower3Bits = IRB.CreateAnd(
        AddrLong, ConstantInt::get(LongTy, 7));
    Lower3Bits = IRB.CreateIntCast(Lower3Bits, ByteTy, false);
    Value *X = IRB.CreateSub(
        ConstantInt::get(ByteTy, 256 - (TypeSize >> MappingScale)),
        Lower3Bits);
    Value *Cmp = IRB.CreateICmpUGE(ShadowValue, X);
    Instruction *CheckTerm = splitBlockAndInsertIfThen(
        cast<Instruction>(Cmp)->getNextNode(), Cmp);
    IRBuilder<> irb3(CheckTerm->getParent(), CheckTerm);
    Instruction *crash = generateCrashCode(irb3, AddrLong, TelltaleValue);
    CloneDebugInfo(OrigIns, crash);
    return;
  }

  Value *Cmp = IRB.CreateICmpNE(ShadowValue, CmpVal);

  Instruction *CheckTerm = splitBlockAndInsertIfThen(
      cast<Instruction>(Cmp)->getNextNode(), Cmp);
  IRBuilder<> irb2(CheckTerm->getParent(), CheckTerm);

  size_t granularity = 1 << MappingScale;
  if (TypeSize < 8 * granularity) {
    // Addr & (granularity - 1)
    Value *Lower3Bits = irb2.CreateAnd(
        AddrLong, ConstantInt::get(LongTy, granularity - 1));
    // (Addr & (granularity - 1)) + size - 1
    Value *LastAccessedByte = irb2.CreateAdd(
        Lower3Bits, ConstantInt::get(LongTy, TypeSize / 8 - 1));
    // (uint8_t) ((Addr & (granularity-1)) + size - 1)
    LastAccessedByte = irb2.CreateIntCast(
        LastAccessedByte, ByteTy, false);
    // ((uint8_t) ((Addr & (granularity-1)) + size - 1)) >= ShadowValue
    Value *cmp2 = irb2.CreateICmpSGE(LastAccessedByte, ShadowValue);

    CheckTerm = splitBlockAndInsertIfThen(CheckTerm, cmp2);
  }

  IRBuilder<> irb3(CheckTerm->getParent(), CheckTerm);
  Instruction *crash = generateCrashCode(irb3, AddrLong, TelltaleValue);
  CloneDebugInfo(OrigIns, crash);
}

// Append 'F' to the list of global ctors.
void AddressSanitizer::appendToGlobalCtors(Module &M, Function *F) {
  // The code is shamelessly stolen from
  // RegisterRuntimeInitializer::insertInitializerIntoGlobalCtorList().
  // LLVM may need a general API function for this.

  FunctionType *FnTy = FunctionType::get(VoidTy, false);
  StructType *ty = StructType::get(
      i32Ty, PointerType::getUnqual(FnTy), NULL);

  Constant *RuntimeCtorInit = ConstantStruct::get(
      ty, ConstantInt::get(i32Ty, 65535), F, NULL);

  // Get the current set of static global constructors and add the new ctor
  // to the list.
  std::vector<Constant *> CurrentCtors;
  GlobalVariable * GVCtor = M.getNamedGlobal(kLLVMGlobalCtors);
  if (GVCtor) {
    CurrentCtors.push_back(RuntimeCtorInit);
    if (Constant *Const = GVCtor->getInitializer()) {
      for (unsigned index = 0; index < Const->getNumOperands(); ++index) {
        CurrentCtors.push_back(cast<Constant>(Const->getOperand(index)));
      }
    }
    // Rename the global variable so that we can name our global
    // kLLVMGlobalCtors
    GVCtor->setName("removed");
    GVCtor->eraseFromParent();
  }

  // We insert this twice, in the beginning and at the end. Just in case.
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
  Module::GlobalListType &globals = M.getGlobalList();

  SmallVector<GlobalVariable *, 16> old_globals;

  for (Module::GlobalListType::iterator G = globals.begin(),
       E = globals.end(); G != E; ++G) {
    Type *ty = cast<PointerType>(G->getType())->getElementType();
    DEBUG(dbgs() << "GLOBAL: " << *G);

    if (!ty->isSized()) continue;
    if (!G->hasInitializer()) continue;
    if (G->getLinkage() != GlobalVariable::ExternalLinkage &&
        G->getLinkage() != GlobalVariable::CommonLinkage  &&
        G->getLinkage() != GlobalVariable::PrivateLinkage  &&
        G->getLinkage() != GlobalVariable::InternalLinkage
        ) {
      // do we care about other linkages?
      continue;
    }
    // TODO(kcc): do something smart if the alignment is large.
    if (G->getAlignment() > RedzoneSize) continue;
    old_globals.push_back(G);
  }

  for (size_t i = 0, n = old_globals.size(); i < n; i++) {
    GlobalVariable *G = old_globals[i];
    PointerType *PtrTy = cast<PointerType>(G->getType());
    Type *ty = PtrTy->getElementType();
    uint64_t SizeInBytes = TD->getTypeStoreSizeInBits(ty) / 8;
    uint64_t right_redzone_size = RedzoneSize +
        (RedzoneSize - (SizeInBytes % RedzoneSize));
    Type *RightRedZoneTy = ArrayType::get(ByteTy, right_redzone_size);

    StructType *new_ty = StructType::get(
        ty, RightRedZoneTy, NULL);
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
    Indices[0] = ConstantInt::get(i32Ty, 0);
    Indices[1] = ConstantInt::get(i32Ty, 0);

    GlobalAlias *alias = new GlobalAlias(
        PtrTy, GlobalValue::InternalLinkage,
        G->getName() + kAsanRedzoneNameSuffix,
        ConstantExpr::getGetElementPtr(new_global, Indices, 2),
        new_global->getParent());

    G->replaceAllUsesWith(alias);
    new_global->takeName(G);

    IRBuilder<> IRB(CtorInsertBefore->getParent(),
                    CtorInsertBefore);
    Value *asan_register_global = M.getOrInsertFunction(
        kAsanRegisterGlobalName, VoidTy, LongTy, LongTy, LongTy, NULL);
    cast<Function>(asan_register_global)->setLinkage(
        Function::ExternalLinkage);

    IRB.CreateCall3(asan_register_global,
                    IRB.CreatePointerCast(new_global, LongTy),
                    ConstantInt::get(LongTy, SizeInBytes),
                    IRB.CreatePointerCast(orig_name_glob, LongTy));

    DEBUG(dbgs() << "NEW GLOBAL:\n" << *new_global << *alias);
  }

  // Now delete all old globals which are replaced with new ones.
  for (size_t i = 0; i < old_globals.size(); i++) {
    old_globals[i]->eraseFromParent();
  }

  DEBUG(dbgs() << M);

  return false;
}

// virtual
bool AddressSanitizer::runOnModule(Module &M) {
  if (!ClAsan) return false;
  // Initialize the private fields. No one has accessed them before.
  TD = getAnalysisIfAvailable<TargetData>();
  if (!TD)
    return false;
  BL = new BlackList(ClBlackListFile);

  CurrentModule = &M;
  C = &(M.getContext());
  LongSize = TD->getPointerSizeInBits();
  LongTy = Type::getIntNTy(*C, LongSize);
  i32Ty = Type::getIntNTy(*C, 32);
  ByteTy  = Type::getInt8Ty(*C);
  BytePtrTy = PointerType::get(ByteTy, 0);
  LongPtrTy = PointerType::get(LongTy, 0);
  i32PtrTy = PointerType::get(i32Ty, 0);
  VoidTy = Type::getVoidTy(*C);
  Fn0Ty = FunctionType::get(VoidTy, false);

  Function *asan_ctor = Function::Create(
      Fn0Ty, GlobalValue::InternalLinkage, kAsanModuleCtorName, &M);
  BasicBlock *asan_ctor_bb = BasicBlock::Create(*C, "", asan_ctor);
  CtorInsertBefore = ReturnInst::Create(*C, asan_ctor_bb);

  // call __asan_init in the module ctor.
  IRBuilder<> IRB(asan_ctor_bb, CtorInsertBefore);
  Value *asan_init = M.getOrInsertFunction(kAsanInitName, VoidTy, NULL);
  cast<Function>(asan_init)->setLinkage(Function::ExternalLinkage);
  IRB.CreateCall(asan_init);

  MappingOffsetLog = LongSize == 32
      ? kDefaultShadowOffset32 : kDefaultShadowOffset64;
  if (ClMappingOffsetLog) {
    MappingOffsetLog = ClMappingOffsetLog;
  }
  MappingScale = kDefaultShadowScale;
  if (ClMappingScale) {
    MappingScale = ClMappingScale;
  }
  // Redzone used for stack and globals is at least 32 bytes.
  // For scales 6 and 7, the redzone has to be 64 and 128 bytes respectively.
  RedzoneSize = max(32, (int)(1 << MappingScale));
  GlobalValue *asan_mapping_offset =
      new GlobalVariable(M, LongTy, true, GlobalValue::LinkOnceODRLinkage,
                     ConstantInt::get(LongTy, 1ULL << MappingOffsetLog),
                     kAsanMappingOffsetName);
  GlobalValue *asan_mapping_scale =
      new GlobalVariable(M, LongTy, true, GlobalValue::LinkOnceODRLinkage,
                         ConstantInt::get(LongTy, MappingScale),
                         kAsanMappingScaleName);

  // Read these globals, otherwise they may be optimized away.
  IRB.CreateLoad(asan_mapping_scale, true);
  IRB.CreateLoad(asan_mapping_offset, true);

  bool res = false;

  if (ClGlobals)
    res |= insertGlobalRedzones(M);

  for (Module::iterator F = M.begin(), E = M.end(); F != E; ++F) {
    if (F->isDeclaration()) continue;
    res |= handleFunction(M, *F);
  }

  appendToGlobalCtors(M, asan_ctor);

  return res;
}

static bool blockHasException(BasicBlock &bb) {
  for (BasicBlock::iterator BI = bb.begin(), BE = bb.end();
       BI != BE; ++BI) {
    // TODO(kcc):
    // Workaround for a strange compile assertion while building 483.xalancbmk
    // If we instrument a basic block which calls llvm.eh.exception
    // llvm later crashes with this:
    // lib/CodeGen/SelectionDAG/FunctionLoweringInfo.cpp:212: void
    //   llvm::FunctionLoweringInfo::clear(): Assertion `CatchInfoFound.size()
    //   == CatchInfoLost.size() && "Not all catch info was assigned to a
    //   landing pad!"' failed.
    if (isa<CallInst>(BI)) {
      CallInst *call = cast<CallInst>(BI);
      Function *func = call->getCalledFunction();
      if (func && func->getNameStr() == "llvm.eh.exception") {
        return true;
      }
    }
  }
  return false;
}

static bool blockOrItsSuccHasException(BasicBlock &bb) {
  if (blockHasException(bb)) return true;
  const TerminatorInst *term = bb.getTerminator();
  if (term->getNumSuccessors() == 1 &&
      blockHasException(*term->getSuccessor(0)))
    return true;
  return false;
}

bool AddressSanitizer::handleFunction(Module &M, Function &F) {
  if (BL->IsIn(F)) return false;
  if (F.getNameStr() == kAsanModuleCtorName) return false;

  if (!ClDebugFunc.empty() && ClDebugFunc != F.getNameStr())
    return false;
  // We want to instrument every address only once per basic block
  // (unless there are calls between uses).
  SmallSet<Value*, 16> TempsToInstrument;
  SmallVector<Instruction*, 16> ToInstrument;

  // Fill the set of memory operations to instrument.
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    if (blockOrItsSuccHasException(*FI)) continue;
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

#ifdef __APPLE__
  // In order to handle the +load methods correctly,
  // we need to insert a call to __asan_init() before each of them.
  // TODO(glider): write a test for it.
  if (F.getNameStr().find(" load]") != std::string::npos) {
    BasicBlock *BB = F.begin();
    Instruction *Before = BB->begin();
    Value *AsanInit = F.getParent()->getOrInsertFunction(kAsanInitName,
                                                          VoidTy, NULL);
    cast<Function>(AsanInit)->setLinkage(Function::ExternalLinkage);
    CallInst::Create(AsanInit, "", Before);
    F.dump();
  }
#endif

  return NumInstrumented > 0 || ChangedStack;
}

static uint64_t ValueForPoison(uint64_t PoisonByte, size_t ShadowRedzoneSize) {
  if (ShadowRedzoneSize == 1) return PoisonByte;
  if (ShadowRedzoneSize == 2) return (PoisonByte << 8) + PoisonByte;
  if (ShadowRedzoneSize == 4)
    return (PoisonByte << 24) + (PoisonByte << 16) +
        (PoisonByte << 8) + (PoisonByte);
  assert(0 && "ShadowRedzoneSize is either 1, 2 or 4");
}

static void PoisonShadowPartialRightRedzone(unsigned char *Shadow,
                                            unsigned long Size,
                                            unsigned long RedzoneSize,
                                            unsigned long ShadowGranularity,
                                            unsigned char Magic) {
  for (unsigned long i = 0; i < RedzoneSize;
       i+= ShadowGranularity, Shadow++) {
    if (i + ShadowGranularity <= Size) {
      *Shadow = 0;  // fully addressable
    } else if (i >= Size) {
      *Shadow = (ShadowGranularity == 128) ? 0xff : Magic;  // unaddressable
    } else {
      *Shadow = Size - i;  // first Size-i bytes are addressable
    }
  }
}

void AddressSanitizer::PoisonStack(const ArrayRef<AllocaInst*> &AllocaVec,
                                   IRBuilder<> IRB,
                                   Value *ShadowBase, bool DoPoison) {
  uint8_t PoisonLeftByte  = MappingScale == 7 ? 0xff : 0xf1;
  uint8_t PoisonMidByte   = MappingScale == 7 ? 0xff : 0xf2;
  uint8_t PoisonRightByte = MappingScale == 7 ? 0xff : 0xf3;

  size_t ShadowRZSize = RedzoneSize >> MappingScale;
  assert(ShadowRZSize >= 1 && ShadowRZSize <= 4);
  Type *RZTy = Type::getIntNTy(*C, ShadowRZSize * 8);
  Type *RZPtrTy = PointerType::get(RZTy, 0);

  Value *PoisonLeft  = ConstantInt::get(RZTy,
    ValueForPoison(DoPoison ? PoisonLeftByte : 0LL, ShadowRZSize));
  Value *PoisonMid   = ConstantInt::get(RZTy,
    ValueForPoison(DoPoison ? PoisonMidByte : 0LL, ShadowRZSize));
  Value *PoisonRight = ConstantInt::get(RZTy,
    ValueForPoison(DoPoison ? PoisonRightByte : 0LL, ShadowRZSize));

  // poison the first red zone.
  IRB.CreateStore(PoisonLeft, IRB.CreateIntToPtr(ShadowBase, RZPtrTy));

  // poison all other red zones.
  uint64_t Pos = RedzoneSize;
  for (size_t i = 0; i < AllocaVec.size(); i++) {
    AllocaInst *AI = AllocaVec[i];
    uint64_t SizeInBytes = getAllocaSizeInBytes(AI);
    uint64_t AlignedSize = getAlignedAllocaSize(AI);
    assert(AlignedSize - SizeInBytes < RedzoneSize);
    Value *Ptr;

    Pos += AlignedSize;

    assert(ShadowBase->getType() == LongTy);
    if (SizeInBytes < AlignedSize) {
      // Poison the partial redzone at right
      Ptr = IRB.CreateAdd(
          ShadowBase, ConstantInt::get(LongTy,
                                        (Pos >> MappingScale) - ShadowRZSize));
      size_t addressible_bytes = RedzoneSize - (AlignedSize - SizeInBytes);
      uint32_t Poison = 0;
      if (DoPoison) {
        PoisonShadowPartialRightRedzone((uint8_t*)&Poison, addressible_bytes,
                                        RedzoneSize,
                                        1ULL << MappingScale, 0xf4);
      }
      Value *partial_poison = ConstantInt::get(RZTy, Poison);
      IRB.CreateStore(partial_poison, IRB.CreateIntToPtr(Ptr, RZPtrTy));
    }

    // Poison the full redzone at right.
    Ptr = IRB.CreateAdd(ShadowBase,
                        ConstantInt::get(LongTy, Pos >> MappingScale));
    Value *Poison = i == AllocaVec.size() - 1 ? PoisonRight : PoisonMid;
    IRB.CreateStore(Poison, IRB.CreateIntToPtr(Ptr, RZPtrTy));

    Pos += RedzoneSize;
  }
}

static const uintptr_t kFrameNameMagic = 0x41B58AB3;

// Find all static Alloca instructions and put
// poisoned red zones around all of them.
bool AddressSanitizer::poisonStackInFunction(Module &M, Function &F) {
  if (!ClStack) return false;
  SmallVector<AllocaInst*, 16> AllocaVec;
  SmallVector<Instruction*, 8> RetVec;
  uint64_t total_size = 0;

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
      if (AI->getAlignment() > RedzoneSize) continue;  // TODO(kcc)
      AllocaVec.push_back(AI);
      uint64_t AlignedSize =  getAlignedAllocaSize(AI);
      total_size += AlignedSize;
    }
  }

  if (AllocaVec.empty()) return false;

  uint64_t LocalStackSize = total_size + (AllocaVec.size() + 1) * RedzoneSize;

  bool DoStackMalloc = ClUseAfterReturn
      && LocalStackSize <= kMaxStackMallocSize;

  Instruction *ins_before = AllocaVec[0];
  IRBuilder<> IRB(ins_before->getParent(), ins_before);

  Value *FunctionName = createPrivateGlobalForString(M, F.getName());
  FunctionName = IRB.CreatePointerCast(FunctionName, LongTy);
  Value *LocalStackBase = NULL;
  if (DoStackMalloc) {
    Value *AsanStackMallocFunc = M.getOrInsertFunction(
        kAsanStackMallocName, LongTy, LongTy, NULL);
    LocalStackBase = IRB.CreateCall(AsanStackMallocFunc,
        ConstantInt::get(LongTy, LocalStackSize));
  } else {
    Type *ByteArrayTy = ArrayType::get(ByteTy, LocalStackSize);
    AllocaInst *MyAlloca =
        new AllocaInst(ByteArrayTy, "MyAlloca", ins_before);
    MyAlloca->setAlignment(RedzoneSize);
    assert(MyAlloca->isStaticAlloca());
    LocalStackBase = IRB.CreatePointerCast(MyAlloca, LongTy);
  }

  // Write the Magic value and the function name constant to the redzone.
  Value *BasePlus0 = IRB.CreateIntToPtr(LocalStackBase, LongPtrTy);
  Value *BasePlus1 = IRB.CreateAdd(LocalStackBase,
                                   ConstantInt::get(LongTy, LongSize/8));
  BasePlus1 = IRB.CreateIntToPtr(BasePlus1, LongPtrTy);
  IRB.CreateStore(ConstantInt::get(LongTy, kFrameNameMagic), BasePlus0);
  IRB.CreateStore(FunctionName, BasePlus1);

  uint64_t Pos = RedzoneSize;
  // Replace Alloca instructions with base+offset.
  for (size_t i = 0; i < AllocaVec.size(); i++) {
    AllocaInst *AI = AllocaVec[i];
    uint64_t AlignedSize = getAlignedAllocaSize(AI);
    assert((AlignedSize % RedzoneSize) == 0);
    Value *NewPtr = BinaryOperator::CreateAdd(
        LocalStackBase, ConstantInt::get(LongTy, Pos), "", AI);
    NewPtr = new IntToPtrInst(NewPtr, AI->getType(), "", AI);

    Pos += AlignedSize + RedzoneSize;
    AI->replaceAllUsesWith(NewPtr);
  }
  assert(Pos == LocalStackSize);

  // Poison the stack redzones at the entry.
  Value *ShadowBase = memToShadow(LocalStackBase, IRB);
  PoisonStack(ArrayRef<AllocaInst*>(AllocaVec), IRB, ShadowBase, true);

  Value *AsanStackFreeFunc = NULL;
  if (DoStackMalloc) {
    AsanStackFreeFunc = M.getOrInsertFunction(
        kAsanStackFreeName, VoidTy, LongTy, LongTy, NULL);
  }

  // Unpoison the stack before all ret instructions.
  for (size_t i = 0; i < RetVec.size(); i++) {
    Instruction *Ret = RetVec[i];
    IRBuilder<> IRBRet(Ret->getParent(), Ret);
    if (DoStackMalloc) {
      IRBRet.CreateCall2(AsanStackFreeFunc, LocalStackBase,
                          ConstantInt::get(LongTy, LocalStackSize));
    } else {
      PoisonStack(ArrayRef<AllocaInst*>(AllocaVec), IRBRet, ShadowBase, false);
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
  for (size_t i = 0; i < Lines.size(); i++) {
    if (Lines[i].startswith(kFunPrefix)) {
      std::string ThisFunc = Lines[i].substr(strlen(kFunPrefix));
      if (Fun.size()) {
        Fun += "|";
      }
      // add ThisFunc replacing * with .*
      for (size_t j = 0; j < ThisFunc.size(); j++) {
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

bool BlackList::IsIn(const Function &F) {
  if (Functions) {
    bool res = Functions->match(F.getNameStr());
    return res;
  }
  return false;
}
