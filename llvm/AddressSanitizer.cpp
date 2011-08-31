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

#include <stdint.h>
#include <stdio.h>
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
static cl::opt<bool> ClUseBTS("asan-use-bts",
       cl::desc("Use the BTS instruction (x86)"), cl::init(false));

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

static const char *kAsanModuleCtorName = "asan.module_ctor";

// Blacklisted functions are not instrumented.
// The blacklist file contains one or more lines like this:
// ---
// fun:FunctionWildCard
// ---
// This is similar to the "ignore" feature of ThreadSanitizer.
// http://code.google.com/p/data-race-test/wiki/ThreadSanitizerIgnores
class BlackList {
 public:
  BlackList(const std::string &path);
  bool IsIn(const Function &F);
 private:
  Regex *functions;
};

struct AddressSanitizer : public ModulePass {
  AddressSanitizer();
  void instrumentMop(Instruction *mop);
  void instrumentAddress(Instruction *orig_mop, IRBuilder<> &irb,
                         Value *Addr, size_t type_size, bool is_w);
  Instruction *generateCrashCode(IRBuilder<> &irb, Value *Addr,
                                 int telltale_value);
  bool instrumentMemIntrinsic(MemIntrinsic *mem_intr);
  void instrumentMemIntrinsicParam(Instruction *orig_mop, Value *addr,
                                   Value *size,
                                   Instruction *insert_before, bool is_w);
  Value *memToShadow(Value *Shadow, IRBuilder<> &irb);
  bool handleFunction(Module &M, Function &F);
  bool poisonStackInFunction(Module &M, Function &F);
  virtual bool runOnModule(Module &M);
  bool insertGlobalRedzones(Module &M);
  void appendToGlobalCtors(Module &M, Function *f);
  BranchInst *splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *cmp);
  static char ID; // Pass identification, replacement for typeid

 private:

  uint64_t getAllocaSizeInBytes(AllocaInst *a) {
    Type *ty = a->getAllocatedType();
    uint64_t size_in_bytes = TD->getTypeStoreSizeInBits(ty) / 8;
    return size_in_bytes;
  }
  uint64_t getAlignedSize(uint64_t size_in_bytes) {
    return ((size_in_bytes + RedzoneSize - 1)
            / RedzoneSize) * RedzoneSize;
  }
  uint64_t getAlignedAllocaSize(AllocaInst *a) {
    uint64_t size_in_bytes = getAllocaSizeInBytes(a);
    return getAlignedSize(size_in_bytes);
  }

  void PoisonStack(const ArrayRef<AllocaInst*> &alloca_v, IRBuilder<> irb,
                   Value *shadow_base, bool do_poison);

  Module      *CurrentModule;
  LLVMContext *C;
  TargetData *TD;
  uint64_t    MappingOffsetLog;
  int         MappingScale;
  size_t      RedzoneSize;
  int         LongSize;
  Type *VoidTy;
  Type *LongTy;
  Type *LongPtrTy;
  Type *i32Ty;
  Type *i32PtrTy;
  Type *ByteTy;
  Type *BytePtrTy;
  FunctionType *Fn0Ty;
  Instruction *asan_ctor_insert_before;
  BlackList *black_list;
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

static void CloneDebugInfo(Instruction *from, Instruction *to) {
  MDNode *dbg = from->getMetadata(LLVMContext::MD_dbg);
  if (dbg)
    to->setMetadata("dbg", dbg);
}

Value *AddressSanitizer::memToShadow(Value *Shadow, IRBuilder<> &irb) {
  // Shadow >> scale
  Shadow = irb.CreateLShr(Shadow, MappingScale);
  if (ClUseBTS) {
    // Generate something like "bts $0x2c,%rcx". This is more compact than
    // "mov $0x100000000000,%rdx; or %rdx,%rcx", but slower.
    char bts[30];
    sprintf(bts, "bts $$%ld, $0", (long)MappingOffsetLog);
    Value *insn = InlineAsm::get(
        FunctionType::get(LongTy, ArrayRef<Type*>(LongTy), false),
        StringRef(bts), StringRef("=r,0"), true);
    Value *res = irb.CreateCall(insn, Shadow);
    return res;
  }
  // (Shadow >> scale) | offset
  return irb.CreateOr(Shadow, ConstantInt::get(LongTy,
                                               1ULL << MappingOffsetLog));
}

void AddressSanitizer::instrumentMemIntrinsicParam(Instruction *orig_mop,
    Value *addr, Value *size, Instruction *insert_before, bool is_w) {
  // Check the first byte.
  {
    IRBuilder<> irb(insert_before->getParent(), insert_before);
    instrumentAddress(orig_mop, irb, addr, 8, is_w);
  }
  // Check the last byte.
  {
    IRBuilder<> irb(insert_before->getParent(), insert_before);
    Value *size_minus_one = irb.CreateSub(
        size, ConstantInt::get(size->getType(), 1));
    size_minus_one = irb.CreateIntCast(size_minus_one, LongTy, false);
    Value *addr_long = irb.CreatePointerCast(addr, LongTy);
    Value *addr_plus_size_minus_one = irb.CreateAdd(addr_long, size_minus_one);
    instrumentAddress(orig_mop, irb, addr_plus_size_minus_one, 8, is_w);
  }
}

// Instrument memset/memmove/memcpy
bool AddressSanitizer::instrumentMemIntrinsic(MemIntrinsic *mem_intr) {
  Value *dst = mem_intr->getDest();
  MemTransferInst *mtran = dyn_cast<MemTransferInst>(mem_intr);
  Value *src = mtran ? mtran->getSource() : NULL;
  Value *length = mem_intr->getLength();

  Constant *const_length = dyn_cast<Constant>(length);
  Instruction *insert_before = mem_intr->getNextNode();
  if (const_length) {
    if (const_length->isNullValue()) return false;
  } else {
    // The size is not a constant so it could be zero -- check at run-time.
    IRBuilder<> irb(insert_before->getParent(), insert_before);

    Value *cmp = irb.CreateICmpNE(length,
                                   Constant::getNullValue(length->getType()));
    BranchInst *term = splitBlockAndInsertIfThen(insert_before, cmp);
    insert_before = term;
  }

  instrumentMemIntrinsicParam(mem_intr, dst, length, insert_before, true);
  if (src)
    instrumentMemIntrinsicParam(mem_intr, src, length, insert_before, false);
  return true;
}

static Value *getLDSTOperand(Instruction *inst) {
  if (LoadInst *ld = dyn_cast<LoadInst>(inst)) {
    return ld->getPointerOperand();
  }
  return cast<StoreInst>(*inst).getPointerOperand();
}

void AddressSanitizer::instrumentMop(Instruction *mop) {
  int is_w = !!isa<StoreInst>(*mop);
  Value *Addr = getLDSTOperand(mop);
  if (ClOpt && ClOptGlobals && isa<GlobalVariable>(Addr)) {
    // We are accessing a global scalar variable. Nothing to catch here.
    return;
  }
  Type *OrigPtrTy = Addr->getType();
  Type *OrigTy = cast<PointerType>(OrigPtrTy)->getElementType();

  assert(OrigTy->isSized());
  unsigned type_size = TD->getTypeStoreSizeInBits(OrigTy);

  if (type_size != 8  && type_size != 16
      && type_size != 32 && type_size != 64 && type_size != 128) {
    // TODO(kcc): do something better.
    return;
  }

  IRBuilder<> irb1(mop->getParent(), mop);
  instrumentAddress(mop, irb1, Addr, type_size, is_w);
}

Instruction *AddressSanitizer::generateCrashCode(
    IRBuilder<> &irb, Value *Addr, int telltale_value) {
  if (ClUseCall) {
    // Here we use a call instead of arch-specific asm to report an error.
    // This is almost always slower (because the codegen needs to generate
    // prologue/epilogue for otherwise leaf functions) and generates more code.
    // This mode could be useful if we can not use SIGILL for some reason.
    //
    // The telltale_value (is_write and size) is encoded in the function name.
    char function_name[100];
    sprintf(function_name, "__asan_report_error_%d", telltale_value);
    Value *asan_report_warning = CurrentModule->getOrInsertFunction(
        function_name, VoidTy, LongTy, NULL);
    CallInst *call = irb.CreateCall(asan_report_warning, Addr);
    return call;
  }

  // Move the failing address to %rax/%eax
  FunctionType *Fn1Ty = FunctionType::get(
      VoidTy, ArrayRef<Type*>(LongTy), false);
  const char *mov_str = LongSize == 32
      ? "mov $0, %eax" : "mov $0, %rax";
  Value *asm_mov = InlineAsm::get(
      Fn1Ty, StringRef(mov_str), StringRef("r"), true);
  irb.CreateCall(asm_mov, Addr);

  // crash with ud2; could use int3, but it is less friendly to gdb.
  // after ud2 put a 1-byte instruction that encodes the access type and size.

  const char *telltale_insns[16] = {
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

  std::string asm_str = "ud2;";
  asm_str += telltale_insns[telltale_value];
  Value *my_asm = InlineAsm::get(Fn0Ty, StringRef(asm_str), 
                                 StringRef(""), true);
  CallInst *asm_call = irb.CreateCall(my_asm);

  // This saves us one jump, but triggers a bug in RA (or somewhere else):
  // while building 483.xalancbmk the compiler goes into infinite loop in
  // llvm::SpillPlacement::iterate() / RAGreedy::growRegion
  // asm_call->setDoesNotReturn();
  return asm_call;
}

void AddressSanitizer::instrumentAddress(Instruction *orig_mop,
                                         IRBuilder<> &irb1, Value *Addr,
                                         size_t type_size, bool is_w) {
  unsigned log_of_size_in_bytes = __builtin_ctz(type_size / 8);
  assert(8U * (1 << log_of_size_in_bytes) == type_size);
  uint8_t telltale_value = is_w * 8 + log_of_size_in_bytes;
  assert(telltale_value < 16);

  Value *AddrLong = irb1.CreatePointerCast(Addr, LongTy);

  Type *ShadowTy  = IntegerType::get(
      *C, max((size_t)8, type_size >> MappingScale));
  Type *ShadowPtrTy = PointerType::get(ShadowTy, 0);
  Value *ShadowPtr = memToShadow(AddrLong, irb1);
  Value *CmpVal = Constant::getNullValue(ShadowTy);
  Value *ShadowValue = irb1.CreateLoad(
      irb1.CreateIntToPtr(ShadowPtr, ShadowPtrTy));

  if (ClExperimental) {
    // Experimental code.
    Value *Lower3Bits = irb1.CreateAnd(
        AddrLong, ConstantInt::get(LongTy, 7));
    Lower3Bits = irb1.CreateIntCast(Lower3Bits, ByteTy, false);
    Value *X = irb1.CreateSub(
        ConstantInt::get(ByteTy, 256 - (type_size >> MappingScale)),
        Lower3Bits);
    Value *Cmp = irb1.CreateICmpUGE(ShadowValue, X);
    Instruction *CheckTerm = splitBlockAndInsertIfThen(
        cast<Instruction>(Cmp)->getNextNode(), Cmp);
    IRBuilder<> irb3(CheckTerm->getParent(), CheckTerm);
    Instruction *crash = generateCrashCode(irb3, AddrLong, telltale_value);
    CloneDebugInfo(orig_mop, crash);
    return;
  }

  Value *Cmp = irb1.CreateICmpNE(ShadowValue, CmpVal);

  Instruction *CheckTerm = splitBlockAndInsertIfThen(
      cast<Instruction>(Cmp)->getNextNode(), Cmp);
  IRBuilder<> irb2(CheckTerm->getParent(), CheckTerm);

  size_t granularity = 1 << MappingScale;
  if (type_size < 8 * granularity) {
    // addr & (granularity - 1)
    Value *Lower3Bits = irb2.CreateAnd(
        AddrLong, ConstantInt::get(LongTy, granularity - 1));
    // (addr & (granularity - 1)) + size - 1
    Value *LastAccessedByte = irb2.CreateAdd(
        Lower3Bits, ConstantInt::get(LongTy, type_size / 8 - 1));
    // (uint8_t) ((addr & (granularity-1)) + size - 1)
    LastAccessedByte = irb2.CreateIntCast(
        LastAccessedByte, ByteTy, false);
    // ((uint8_t) ((addr & (granularity-1)) + size - 1)) >= ShadowValue
    Value *cmp2 = irb2.CreateICmpSGE(LastAccessedByte, ShadowValue);

    CheckTerm = splitBlockAndInsertIfThen(CheckTerm, cmp2);
  }

  IRBuilder<> irb3(CheckTerm->getParent(), CheckTerm);
  Instruction *crash = generateCrashCode(irb3, AddrLong, telltale_value);
  CloneDebugInfo(orig_mop, crash);
}

// Append 'f' to the list of global ctors.
void AddressSanitizer::appendToGlobalCtors(Module &M, Function *f) {
  // The code is shamelessly stolen from
  // RegisterRuntimeInitializer::insertInitializerIntoGlobalCtorList().
  // LLVM may need a general API function for this.

  FunctionType *FnTy = FunctionType::get(VoidTy, false);
  StructType *ty = StructType::get(
      i32Ty, PointerType::getUnqual(FnTy), NULL);

  Constant *RuntimeCtorInit = ConstantStruct::get(
      ty, ConstantInt::get (i32Ty, 65535), f, NULL);

  // Get the current set of static global constructors and add the new ctor
  // to the list.
  std::vector<Constant *> CurrentCtors;
  GlobalVariable * GVCtor = M.getNamedGlobal ("llvm.global_ctors");
  if (GVCtor) {
    CurrentCtors.push_back(RuntimeCtorInit);
    if (Constant *Const = GVCtor->getInitializer()) {
      for (unsigned index = 0; index < Const->getNumOperands(); ++index) {
        CurrentCtors.push_back (cast<Constant>(Const->getOperand (index)));
      }
    }
    // Rename the global variable so that we can name our global
    // llvm.global_ctors.
    GVCtor->setName ("removed");
    GVCtor->eraseFromParent();
  }

  // We insert this twice, in the beginning and at the end. Just in case.
  CurrentCtors.push_back(RuntimeCtorInit);

  // Create a new initializer.
  ArrayType * AT = ArrayType::get (RuntimeCtorInit->getType(),
                                         CurrentCtors.size());
  Constant *NewInit = ConstantArray::get (AT, CurrentCtors);

  // Create the new llvm.global_ctors global variable and replace all uses of
  // the old global variable with the new one.
  new GlobalVariable (M,
                      NewInit->getType(),
                      false,
                      GlobalValue::AppendingLinkage,
                      NewInit,
                      "llvm.global_ctors");
}

// This function replaces all global variables with new variables that have
// trailing redzones. It also creates a function that poisons
// redzones and inserts this function into llvm.global_ctors.
bool AddressSanitizer::insertGlobalRedzones(Module &M) {
  Module::GlobalListType &globals = M.getGlobalList();

  SmallVector<GlobalVariable *, 16> old_globals;

  for (Module::GlobalListType::iterator G = globals.begin(),
       E = globals.end(); G != E; ++G) {
    GlobalVariable &orig_global = *G;
    PointerType *ptrty = cast<PointerType>(orig_global.getType());
    Type *ty = ptrty->getElementType();
    if (ClDebug) {
      errs() << "GLOBAL: " << orig_global;
    }

    if (!ty->isSized()) continue;
    if (!orig_global.hasInitializer()) continue;
    if (orig_global.isConstant()) continue;  // do we care about constants?
    if (orig_global.getLinkage() != GlobalVariable::ExternalLinkage &&
        orig_global.getLinkage() != GlobalVariable::CommonLinkage  &&
        orig_global.getLinkage() != GlobalVariable::PrivateLinkage  &&
        orig_global.getLinkage() != GlobalVariable::InternalLinkage
        ) {
      // do we care about other linkages?
      continue;
    }
    // TODO(kcc): do something smart if the alignment is large.
    if (orig_global.getAlignment() > RedzoneSize) continue;

    uint64_t size_in_bytes = TD->getTypeStoreSizeInBits(ty) / 8;
    uint64_t right_redzone_size = RedzoneSize +
        (RedzoneSize - (size_in_bytes % RedzoneSize));
    Type *RightRedZoneTy = ArrayType::get(ByteTy, right_redzone_size);

    StructType *new_ty = StructType::get(
        ty, RightRedZoneTy, NULL);
    Constant *new_initializer = ConstantStruct::get(
        new_ty,
        orig_global.getInitializer(),
        Constant::getNullValue(RightRedZoneTy),
        NULL);

    GlobalVariable *orig_name_glob =
        createPrivateGlobalForString(M, orig_global.getName());

    // Create a new global variable with enough space for a redzone.
    GlobalVariable *new_global = new GlobalVariable(
        M, new_ty, orig_global.isConstant(), orig_global.getLinkage(),
        new_initializer,
        "",
        &orig_global, orig_global.isThreadLocal());
    new_global->copyAttributesFrom(&orig_global);
    new_global->setAlignment(RedzoneSize);

    Constant *Indices[2];
    Indices[0] = ConstantInt::get(i32Ty, 0);
    Indices[1] = ConstantInt::get(i32Ty, 0);

    GlobalAlias *alias = new GlobalAlias(
        ptrty, GlobalValue::InternalLinkage,
        orig_global.getName() + "_asanRZ",
        ConstantExpr::getGetElementPtr(new_global, Indices, 2),
        new_global->getParent());

    orig_global.replaceAllUsesWith(alias);
    new_global->takeName(&orig_global);
    old_globals.push_back(&orig_global);

    IRBuilder<> irb(asan_ctor_insert_before->getParent(),
                    asan_ctor_insert_before);
    Value *asan_register_global = M.getOrInsertFunction(
        "__asan_register_global", VoidTy, LongTy, LongTy, LongTy, NULL);
    cast<Function>(asan_register_global)->setLinkage(
        Function::ExternalLinkage);

    irb.CreateCall3(asan_register_global,
                   irb.CreatePointerCast(new_global, LongTy),
                   ConstantInt::get(LongTy, size_in_bytes),
                   irb.CreatePointerCast(orig_name_glob, LongTy)
                   );

    if (ClDebug) {
      errs() << "   " <<  *ty << " --- " << *new_ty << "\n";
      errs() << *new_initializer << "\n";
      errs() << *new_global << "\n";
      errs() << *alias << "\n";
    }
  }

  // Now delete all old globals which are replaced with new ones.
  for (size_t i = 0; i < old_globals.size(); i++) {
    old_globals[i]->eraseFromParent();
  }

  if (ClDebug >= 2) {
    errs() << M;
  }

  return false;
}
//virtual
bool AddressSanitizer::runOnModule(Module &M) {
  if (!ClAsan) return false;
  // Initialize the private fields. No one has accessed them before.
  TD = getAnalysisIfAvailable<TargetData>();
  if (!TD)
    return false;
  black_list = new BlackList(ClBlackListFile);

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
  asan_ctor_insert_before = ReturnInst::Create(*C, asan_ctor_bb);

  // call __asan_init in the module ctor.
  IRBuilder<> irb(asan_ctor_bb, asan_ctor_insert_before);
  Value *asan_init = M.getOrInsertFunction("__asan_init", VoidTy, NULL);
  cast<Function>(asan_init)->setLinkage(Function::ExternalLinkage);
  irb.CreateCall(asan_init);

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
                     "__asan_mapping_offset");
  GlobalValue *asan_mapping_scale =
      new GlobalVariable(M, LongTy, true, GlobalValue::LinkOnceODRLinkage,
                         ConstantInt::get(LongTy, MappingScale),
                         "__asan_mapping_scale");

  // Read these globals, otherwise they may be optimized away.
  irb.CreateLoad(asan_mapping_scale, true);
  irb.CreateLoad(asan_mapping_offset, true);

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
  if (black_list->IsIn(F)) return false;
  if (F.getNameStr() == kAsanModuleCtorName) return false;

  if (!ClDebugFunc.empty() && ClDebugFunc != F.getNameStr())
    return false;
  // We want to instrument every address only once per basic block
  // (unless there are calls between uses).
  SmallSet<Value*, 16> temps_to_instrument;
  SmallVector<Instruction*, 16> to_instrument;

  // Fill the set of memory operations to instrument.
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    if (blockOrItsSuccHasException(*FI)) continue;
    temps_to_instrument.clear();
    for (BasicBlock::iterator BI = FI->begin(), BE = FI->end();
         BI != BE; ++BI) {
      if ((isa<LoadInst>(BI) && ClInstrumentReads) ||
          (isa<StoreInst>(BI) && ClInstrumentWrites)) {
        Value *addr = getLDSTOperand(BI);
        if (ClOpt && ClOptSameTemp) {
          if (!temps_to_instrument.insert(addr))
            continue; // We've seen this temp in the current BB.
        }
      } else if (isa<MemIntrinsic>(BI) && ClMemIntrin) {
        ; // ok, take it.
      } else {
        if (isa<CallInst>(BI)) {
          // A call inside BB.
          temps_to_instrument.clear();
        }
        continue;
      }
      to_instrument.push_back(BI);
    }
  }

  // Instrument.
  int n_instrumented = 0;
  for (size_t i = 0, n = to_instrument.size(); i != n; i++) {
    Instruction *Inst = to_instrument[i];
    if (ClDebugMin < 0 || ClDebugMax < 0 ||
        (n_instrumented >= ClDebugMin && n_instrumented <= ClDebugMax)) {
      if (isa<StoreInst>(Inst) || isa<LoadInst>(Inst))
        instrumentMop(Inst);
      else
        instrumentMemIntrinsic(cast<MemIntrinsic>(Inst));
    }
    n_instrumented++;
  }

  if (!ClDebugFunc.empty() || ClDebug)
    errs() << F;

  bool changed_stack = poisonStackInFunction(M, F);

#ifdef __APPLE__
  // In order to handle the +load methods correctly,
  // we need to insert a call to __asan_init() before each of them.
  // TODO(glider): write a test for it.
  if (F.getNameStr().find(" load]") != std::string::npos) {
    BasicBlock *BB = F.begin();
    Instruction *Before = BB->begin();
    Value *asan_init = F.getParent()->getOrInsertFunction("__asan_init",
                                                          VoidTy, NULL);
    cast<Function>(asan_init)->setLinkage(Function::ExternalLinkage);
    CallInst::Create(asan_init, "", Before);
    F.dump();
  }
#endif

  return n_instrumented > 0 || changed_stack;
}

static uint64_t ValueForPoison(uint64_t poison_byte, size_t ShadowRedzoneSize) {
  if (ShadowRedzoneSize == 1) return poison_byte;
  if (ShadowRedzoneSize == 2) return (poison_byte << 8) + poison_byte;
  if (ShadowRedzoneSize == 4)
    return (poison_byte << 24) + (poison_byte << 16) +
        (poison_byte << 8) + (poison_byte);
  assert(0 && "ShadowRedzoneSize is either 1, 2 or 4");
}

static void PoisonShadowPartialRightRedzone(unsigned char *shadow,
                                            unsigned long size,
                                            unsigned long redzone_size,
                                            unsigned long shadow_granularity,
                                            unsigned char magic) {
  for (unsigned long i = 0; i < redzone_size;
       i+= shadow_granularity, shadow++) {
    if (i + shadow_granularity <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow = (shadow_granularity == 128) ? 0xff : magic;  // unaddressable
    } else {
      *shadow = size - i;  // first size-i bytes are addressable
    }
  }
}

void AddressSanitizer::PoisonStack(const ArrayRef<AllocaInst*> &alloca_v, 
                                   IRBuilder<> irb,
                                   Value *shadow_base, bool do_poison) {
  uint8_t poison_left_byte  = MappingScale == 7 ? 0xff : 0xf1;
  uint8_t poison_mid_byte   = MappingScale == 7 ? 0xff : 0xf2;
  uint8_t poison_right_byte = MappingScale == 7 ? 0xff : 0xf3;

  size_t ShadowRZSize = RedzoneSize >> MappingScale;
  assert(ShadowRZSize >= 1 && ShadowRZSize <= 4);
  Type *RZTy = Type::getIntNTy(*C, ShadowRZSize * 8);
  Type *RZPtrTy = PointerType::get(RZTy, 0);

  Value *poison_left  = ConstantInt::get(RZTy,
    ValueForPoison(do_poison ? poison_left_byte : 0LL, ShadowRZSize));
  Value *poison_mid   = ConstantInt::get(RZTy,
    ValueForPoison(do_poison ? poison_mid_byte : 0LL, ShadowRZSize));
  Value *poison_right = ConstantInt::get(RZTy,
    ValueForPoison(do_poison ? poison_right_byte : 0LL, ShadowRZSize));

  // poison the first red zone.
  irb.CreateStore(poison_left, irb.CreateIntToPtr(shadow_base, RZPtrTy));

  // poison all other red zones.
  uint64_t pos = RedzoneSize;
  for (size_t i = 0; i < alloca_v.size(); i++) {
    AllocaInst *a = alloca_v[i];
    uint64_t size_in_bytes = getAllocaSizeInBytes(a);
    uint64_t aligned_size = getAlignedAllocaSize(a);
    assert(aligned_size - size_in_bytes < RedzoneSize);
    Value *ptr;

    pos += aligned_size;

    assert(shadow_base->getType() == LongTy);
    if (size_in_bytes < aligned_size) {
      // Poison the partial redzone at right
      ptr = irb.CreateAdd(
          shadow_base, ConstantInt::get(LongTy,
                                        (pos >> MappingScale) - ShadowRZSize));
      size_t addressible_bytes = RedzoneSize - (aligned_size - size_in_bytes);
      uint32_t poison = 0;
      if (do_poison) {
        PoisonShadowPartialRightRedzone((uint8_t*)&poison, addressible_bytes,
                                        RedzoneSize,
                                        1ULL << MappingScale, 0xf4);
      }
      Value *partial_poison = ConstantInt::get(RZTy, poison);
      irb.CreateStore(partial_poison, irb.CreateIntToPtr(ptr, RZPtrTy));
    }

    // Poison the full redzone at right.
    ptr = irb.CreateAdd(shadow_base,
                        ConstantInt::get(LongTy, pos >> MappingScale));
    Value *poison = i == alloca_v.size() - 1 ? poison_right : poison_mid;
    irb.CreateStore(poison, irb.CreateIntToPtr(ptr, RZPtrTy));

    pos += RedzoneSize;
  }
}

static const uintptr_t kFrameNameMagic = 0x41B58AB3;

// Find all static Alloca instructions and put
// poisoned red zones around all of them.
bool AddressSanitizer::poisonStackInFunction(Module &M, Function &F) {
  if (!ClStack) return false;
  SmallVector<AllocaInst*, 16> alloca_v;
  SmallVector<Instruction*, 8> ret_v;
  uint64_t total_size = 0;

  // Filter out Alloca instructions we want (and can) handle.
  // Collect Ret instructions.
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    BasicBlock &BB = *FI;
    for (BasicBlock::iterator BI = BB.begin(), BE = BB.end();
         BI != BE; ++BI) {
      if (isa<ReturnInst>(BI)) {
          ret_v.push_back(BI);
          continue;
      }

      AllocaInst *a = dyn_cast<AllocaInst>(BI);
      if (!a) continue;
      if (a->isArrayAllocation()) continue;
      if (!a->isStaticAlloca()) continue;
      if (!a->getAllocatedType()->isSized()) continue;
      if (a->getAlignment() > RedzoneSize) continue;  // TODO(kcc)
      alloca_v.push_back(a);
      uint64_t aligned_size =  getAlignedAllocaSize(a);
      total_size += aligned_size;
    }
  }

  if (alloca_v.empty()) return false;

  uint64_t LocalStackSize = total_size + (alloca_v.size() + 1) * RedzoneSize;

  bool DoStackMalloc = ClUseAfterReturn
      && LocalStackSize <= kMaxStackMallocSize;

  Instruction *ins_before = alloca_v[0];
  IRBuilder<> irb(ins_before->getParent(), ins_before);

  Value *FunctionName = createPrivateGlobalForString(M, F.getName());
  FunctionName = irb.CreatePointerCast(FunctionName, LongTy);
  Value *LocalStackBase = NULL;
  if (DoStackMalloc) {
    Value *AsanStackMallocFunc = M.getOrInsertFunction(
        "__asan_stack_malloc", LongTy, LongTy, NULL);
    LocalStackBase = irb.CreateCall(AsanStackMallocFunc,
        ConstantInt::get(LongTy, LocalStackSize));
  } else {
    Type *ByteArrayTy = ArrayType::get(ByteTy, LocalStackSize);
    AllocaInst *my_alloca =
        new AllocaInst(ByteArrayTy, "my_alloca", ins_before);
    my_alloca->setAlignment(RedzoneSize);
    assert(my_alloca->isStaticAlloca());
    LocalStackBase = irb.CreatePointerCast(my_alloca, LongTy);
  }

  // Write the magic value and the function name constant to the redzone.
  Value *BasePlus0 = irb.CreateIntToPtr(LocalStackBase, LongPtrTy);
  Value *BasePlus1 = irb.CreateAdd(LocalStackBase,
                                   ConstantInt::get(LongTy, LongSize/8));
  BasePlus1 = irb.CreateIntToPtr(BasePlus1, LongPtrTy);
  irb.CreateStore(ConstantInt::get(LongTy, kFrameNameMagic), BasePlus0);
  irb.CreateStore(FunctionName, BasePlus1);

  uint64_t pos = RedzoneSize;
  // Replace Alloca instructions with base+offset.
  for (size_t i = 0; i < alloca_v.size(); i++) {
    AllocaInst *a = alloca_v[i];
    uint64_t aligned_size = getAlignedAllocaSize(a);
    assert((aligned_size % RedzoneSize) == 0);
    Value *new_ptr = BinaryOperator::CreateAdd(
        LocalStackBase, ConstantInt::get(LongTy, pos), "", a);
    new_ptr = new IntToPtrInst(new_ptr, a->getType(), "", a);

    pos += aligned_size + RedzoneSize;
    a->replaceAllUsesWith(new_ptr);
  }
  assert(pos == LocalStackSize);

  // Poison the stack redzones at the entry.
  Value *shadow_base = memToShadow(LocalStackBase, irb);
  PoisonStack(ArrayRef<AllocaInst*>(alloca_v), irb, shadow_base, true);

  Value *AsanStackFreeFunc = NULL;
  if (DoStackMalloc) {
    AsanStackFreeFunc = M.getOrInsertFunction(
        "__asan_stack_free", VoidTy, LongTy, LongTy, NULL);
  }

  // Unpoison the stack before all ret instructions.
  for (size_t i = 0; i < ret_v.size(); i++) {
    Instruction *ret = ret_v[i];
    IRBuilder<> irb_ret(ret->getParent(), ret);
    if (DoStackMalloc) {
      irb_ret.CreateCall2(AsanStackFreeFunc, LocalStackBase,
                          ConstantInt::get(LongTy, LocalStackSize));
    } else {
      PoisonStack(ArrayRef<AllocaInst*>(alloca_v), irb_ret, shadow_base, false);
    }
  }

  if (ClDebugStack)
    errs() << F;

  // errs() << F.getNameStr() << "\n" << F << "\n";
  return true;
}

BlackList::BlackList(const std::string &path) {
  functions = NULL;
  const char *kFunPrefix = "fun:";
  if (!ClBlackListFile.size()) return;
  std::string fun;

  OwningPtr<MemoryBuffer> File;
  if (error_code ec = MemoryBuffer::getFile(ClBlackListFile.c_str(), File)) {
    errs() << ec.message();
    exit(1);
  }
  MemoryBuffer *buff = File.take();
  const char *data = buff->getBufferStart();
  size_t data_len = buff->getBufferSize();
  SmallVector<StringRef, 16> lines;
  SplitString(StringRef(data, data_len), lines, "\n\r");
  for (size_t i = 0; i < lines.size(); i++) {
    if (lines[i].startswith(kFunPrefix)) {
      std::string this_fun = lines[i].substr(strlen(kFunPrefix));
      if (fun.size()) {
        fun += "|";
      }
      // add this_fun replacing * with .*
      for (size_t j = 0; j < this_fun.size(); j++) {
        if (this_fun[j] == '*')
          fun += '.';
        fun += this_fun[j];
      }
    }
  }
  if (fun.size()) {
    // errs() << fun << "\n";
    functions = new Regex(fun);
  }
}

bool BlackList::IsIn(const Function &F) {
  if (functions) {
    bool res = functions->match(F.getNameStr());
    // errs() << "IsIn: " << res << " " << F.getNameStr() << "\n";
    return res;
  }
  return false;
}
