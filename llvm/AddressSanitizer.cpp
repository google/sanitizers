/* Copyright 2011 Google Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

// This file is a part of AddressSanitizer, an address sanity checker.
// Author: Alexander Potapenko
// Author: Kostya Serebryany

#define DEBUG_TYPE "AddressSanitizer"

#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/CallingConv.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/InlineAsm.h"
#include "llvm/InstrTypes.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Type.h"

#include <stdint.h>
#include <stdio.h>

#include "ignore.h"  // From ThreadSanitizer.

#include "asan_rtl.h"

using namespace llvm;
using namespace std;

// Command-line flags. {{{1
static cl::opt<bool> ClAsan("asan",
       cl::desc("enable AddressSanitizer"), cl::init(true));
static cl::opt<bool> ClInstrumentReads("asan-instrument-reads",
       cl::desc("instrument read instructions"), cl::init(true));
static cl::opt<bool> ClInstrumentWrites("asan-instrument-writes",
       cl::desc("instrument write instructions"), cl::init(true));
static cl::opt<bool> ClShadow("asan-shadow",
       cl::desc("Use shadow memory"), cl::init(true));
static cl::opt<bool> ClStack("asan-stack",
       cl::desc("Handle stack memory"), cl::init(false));
static cl::opt<bool> ClByteToByteShadow("asan-byte-to-byte-shadow",
       cl::desc("Use full (byte-to-byte) shadow mapping"), cl::init(false));
static cl::opt<bool>  ClCrOS("asan-cros",
       cl::desc("Instrument for 32-bit ChromeOS"), cl::init(false));
static cl::opt<string>  IgnoreFile("asan-ignore",
       cl::desc("File containing the list of functions to ignore "
                        "during instrumentation"));

static cl::opt<string> ClDebugFunc("asan-debug-func", cl::desc("Debug func"));
static cl::opt<int> ClDebugMin("asan-debug-min", 
                               cl::desc("Debug min inst"), cl::init(-1));
static cl::opt<int> ClDebugMax("asan-debug-max", 
                               cl::desc("Debug man inst"), cl::init(-1));

// }}}

// Define the Printf function used by the ignore machinery.
void Printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  fflush(stderr);
  va_end(args);
}


namespace {

const unsigned kAsanStackAlignment = 64;
const unsigned kAsanStackRedzone = 64;

struct AddressSanitizer : public ModulePass {
  AddressSanitizer();
  void instrumentMop(BasicBlock::iterator &BI);
  void instrumentInMemoryLoad(BasicBlock::iterator &BI, Value *load, Value *Addr, int size, int teltale);
  Value *getPoisonConst(int size);
  Value *memToShadow(Value *Shadow, IRBuilder<> &irb);
  bool handleFunction(Function &F);
  bool poisonStackInFunction(Function &F);
  virtual bool runOnModule(Module &M);
  BranchInst *splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *cmp);
  static char ID; // Pass identification, replacement for typeid

 private:

  uint64_t getAllocaSizeInBytes(AllocaInst *a) {
    const Type *ty = a->getAllocatedType();
    uint64_t size_in_bytes = TD->getTypeStoreSizeInBits(ty) / 8;
    return size_in_bytes;
  }
  uint64_t getAlignedAllocaSize(AllocaInst *a) {
    uint64_t size_in_bytes = getAllocaSizeInBytes(a);
    uint64_t aligned_size = ((size_in_bytes + kAsanStackAlignment - 1)
                             / kAsanStackAlignment) * kAsanStackAlignment;
    return aligned_size;
  }

  void PoisonStack(SmallVector<AllocaInst*, 16> &alloca_v, IRBuilder<> irb,
                   Value *shadow_base, bool do_poison);

  Value *asan_slow_path;
  Value *asan_addr;
  Value *asan_aux;
  LLVMContext *Context;
  TargetData *TD;
  int         LongSize;
  const Type *VoidTy;
  const Type *LongTy;
  const Type *LongPtrTy;
  const Type *ByteTy;
  const Type *i32Ty;
  const Type *i64Ty;
  const Type *BytePtrTy;
  const Type *i64PtrTy;
  SmallSet<Instruction*, 16> to_instrument;
};
}  // namespace

char AddressSanitizer::ID = 0;
#ifdef ASAN_LLVM_PLUGIN
// This code is temporary (we build the plugin with some old version of 
// llvm which comes with ubuntu 10.04)
AddressSanitizer::AddressSanitizer() : ModulePass(&ID) { }
RegisterPass<AddressSanitizer> X("asan",
                                 "AddressSanitizer: detects use-after-free and out-of-bounds bugs.");
#else
INITIALIZE_PASS(AddressSanitizer, "asan",
    "AddressSanitizer: detects use-after-free and out-of-bounds bugs.", false, false)
AddressSanitizer::AddressSanitizer() : ModulePass(ID) { }
ModulePass *llvm::createAddressSanitizerPass() {
  return new AddressSanitizer();
}
#endif


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
BranchInst *AddressSanitizer::splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *Cmp) {
  BasicBlock *Head = SplitBefore->getParent();
  BasicBlock *Tail = Head->splitBasicBlock(SplitBefore);
  TerminatorInst *HeadOldTerm = Head->getTerminator();
  BasicBlock *NewBasicBlock =
      BasicBlock::Create(*Context, "", Head->getParent());
  BranchInst *HeadNewTerm = BranchInst::Create(/*ifTrue*/NewBasicBlock,
                                               /*ifFalse*/Tail,
                                               Cmp);
  ReplaceInstWithInst(HeadOldTerm, HeadNewTerm);

  BranchInst *CheckTerm = BranchInst::Create(Tail, NewBasicBlock);
  return CheckTerm;
}

static void CloneDebugInfo(Instruction *from, Instruction *to) {
  MDNode *dbg = from->getMetadata("dbg");  // newer versions allow MD_dbg.
  if (dbg)
    to->setMetadata("dbg", dbg);
}


Value *AddressSanitizer::memToShadow(Value *Shadow, IRBuilder<> &irb) {
  if (ClByteToByteShadow) {
    // Shadow |= kFullLowShadowMask
    Shadow = irb.CreateOr(
        Shadow, ConstantInt::get(LongTy, kFullLowShadowMask));
    // Shadow &= ~kFullHighShadowMask
    return irb.CreateAnd(
        Shadow, ConstantInt::get(LongTy, ~kFullHighShadowMask));
  }
  // Shadow >> 3
  Shadow = irb.CreateLShr(Shadow, 3);
  uint64_t mask = TD->getPointerSize() == 4
      ? (ClCrOS ? kCROSShadowMask32 : kCompactShadowMask32)
      : kCompactShadowMask64;
  // (Shadow >> 3) | mask
  return irb.CreateOr(Shadow, ConstantInt::get(LongTy, mask));
}

void AddressSanitizer::instrumentMop(BasicBlock::iterator &BI) {
  Instruction *mop = BI;
  int is_store = !!isa<StoreInst>(*mop);
  Value *Addr = is_store
      ? cast<StoreInst>(*mop).getPointerOperand()
      : cast<LoadInst>(*mop).getPointerOperand();
  const Type *OrigPtrTy = Addr->getType();
  const Type *OrigTy = cast<PointerType>(OrigPtrTy)->getElementType();
  bool in_mem_needs_extra_load = isa<StoreInst>(*mop);

  unsigned type_size = 0;  // in bits
  if (OrigTy->isSized()) {
    type_size = TD->getTypeStoreSizeInBits(OrigTy);
  } else {
    errs() << "Type " << *OrigTy << " has unknown size!\n";
    assert(false);
  }

  if (type_size != 8  && type_size != 16
      && type_size != 32 && type_size != 64) {
    // TODO(kcc): do something better.
    return;
  }

  uint8_t telltale_value = is_store * 16 + (type_size / 8);

  if (!(OrigTy->isIntOrIntVectorTy() || OrigTy->isPointerTy()) ||
      TD->getTypeSizeInBits(OrigTy) != type_size) {
    // This type is unsupported by the ICMP instruction. Cast it to the int of
    // appropriate size.
    OrigTy = IntegerType::get(*Context, type_size);
    OrigPtrTy = PointerType::get(OrigTy, 0);
    in_mem_needs_extra_load = true;
  }

  if (ClShadow == false) {
    Instruction *load_to_check = mop;
    if (in_mem_needs_extra_load) {
      if (OrigPtrTy != Addr->getType())
        Addr = new BitCastInst(Addr, OrigPtrTy, "", mop);
      load_to_check = new LoadInst(Addr, "", mop);
      instrumentInMemoryLoad(BI, load_to_check, Addr, type_size, telltale_value);
    } else {
      BI++;
      instrumentInMemoryLoad(BI, load_to_check, Addr, type_size, telltale_value);
    }
    return;
  }

  IRBuilder<> irb1(BI->getParent(), BI);
  Value *AddrLong = irb1.CreatePointerCast(Addr, LongTy);

  const Type *ShadowTy    = ClByteToByteShadow ? OrigTy    : ByteTy;
  const Type *ShadowPtrTy = ClByteToByteShadow ? OrigPtrTy : BytePtrTy;
  Value *ShadowPtr = memToShadow(AddrLong, irb1);
  Value *CmpVal = Constant::getNullValue(ShadowTy);
  Value *PaddedShadowPtr = ShadowPtr;
  if (ClByteToByteShadow) {
    // ShadowPadded = Shadow + kBankPadding;
    PaddedShadowPtr = irb1.CreateAdd(
        ShadowPtr, ConstantInt::get(LongTy, kBankPadding));
  }
  Value *ShadowValue = irb1.CreateLoad(
      irb1.CreateIntToPtr(PaddedShadowPtr, ShadowPtrTy));
  // If the shadow value is non-zero, write to the check address, else
  // continue executing the old code.
  Value *Cmp = irb1.CreateICmpNE(ShadowValue, CmpVal);
  // Split the mop and the successive code into a separate block.
  // Note that it invalidates the iterators used in handleFunction(),
  // but we're ok with that as long as we break from the loop immediately
  // after insrtumentMop().

  Instruction *CheckTerm = splitBlockAndInsertIfThen(BI, Cmp);
  IRBuilder<> irb2(CheckTerm->getParent(), CheckTerm);

  Value *UpdateShadowIntPtr = irb2.CreateShl(ShadowPtr, ClCrOS ? 2 : 1);
  Value *CheckPtr = irb2.CreateIntToPtr(UpdateShadowIntPtr, BytePtrTy);

  if (!ClByteToByteShadow && type_size != 64) {
    // addr & 7
    Value *Lower3Bits = irb2.CreateAnd(
        AddrLong, ConstantInt::get(LongTy, 7));
    // (addr & 7) + size
    Value *LastAccessedByte = irb2.CreateAdd(
        Lower3Bits, ConstantInt::get(LongTy, type_size / 8));
    // (uint8_t) ((addr & 7) + size)
    LastAccessedByte = irb2.CreateIntCast(
        LastAccessedByte, ByteTy, false);
    // ((uint8_t) ((addr & 7) + size)) > ShadowValue
    Value *cmp2 = irb2.CreateICmpSGT(LastAccessedByte, ShadowValue);

    CheckTerm = splitBlockAndInsertIfThen(CheckTerm, cmp2);
  }

  IRBuilder<> irb3(CheckTerm->getParent(), CheckTerm);

  if (!ClByteToByteShadow) {
    Value *ShadowLongPtr = irb3.CreateIntToPtr(ShadowPtr, LongPtrTy);
    irb3.CreateStore(AddrLong, ShadowLongPtr);
  }
  Value *TellTale = ConstantInt::get(ByteTy, telltale_value);
  Instruction *CheckStoreInst = irb3.CreateStore(TellTale, CheckPtr);
  CloneDebugInfo(mop, CheckStoreInst);
}

//virtual
bool AddressSanitizer::runOnModule(Module &M) {
  if (!ClAsan) return false;
  // Initialize the private fields. No one has accessed them before.
  TD = getAnalysisIfAvailable<TargetData>();
  if (!TD)
    return false;
  Context = &(M.getContext());
  LongSize = TD->getPointerSizeInBits();
  LongTy = Type::getIntNTy(*Context, LongSize);
  i32Ty = Type::getIntNTy(*Context, 32);
  i64Ty = Type::getIntNTy(*Context, 64);
  ByteTy  = Type::getInt8Ty(*Context);
  BytePtrTy = PointerType::get(ByteTy, 0);
  LongPtrTy = PointerType::get(LongTy, 0);
  i64PtrTy = PointerType::get(i64Ty, 0);
  VoidTy = Type::getVoidTy(*Context);
  asan_slow_path = M.getOrInsertFunction("asan_slow_path",
       VoidTy, LongTy, LongTy, (Type*)0);

  asan_addr = new GlobalVariable(M, LongTy, /*isConstant*/false,
      GlobalValue::ExternalWeakLinkage, /*Initializer*/0, "__asan_addr",
      /*InsertBefore*/0, /*ThreadLocal*/false);
  asan_aux = new GlobalVariable(M, ByteTy, /*isConstant*/false,
      GlobalValue::ExternalWeakLinkage, /*Initializer*/0, "__asan_aux",
      /*InsertBefore*/0, /*ThreadLocal*/false);

  uintptr_t flag_value = AsanFlagShouldBePresent;
  flag_value |= 1 << (LongSize == 64 ? AsanFlag64 : AsanFlag32);
  if (ClCrOS)
    flag_value |= 1 << AsanFlagCrOS;

  if (ClShadow) {
    if (ClByteToByteShadow)
      flag_value |= 1 << AsanFlagByteToByteShadow;
    else
      flag_value |= 1 << AsanFlagByteToQwordShadow;
  } else {
    flag_value |= 1<< AsanFlagInMemoryPoison;
  }

  bool res = false;
  for (Module::iterator F = M.begin(), E = M.end(); F != E; ++F) {
    if (F->isDeclaration()) continue;
    res |= handleFunction(*F);
  }
  return res;
}

static IgnoreLists *ReadIgnores() {
  IgnoreLists *res = new IgnoreLists;
  if (IgnoreFile.size()) {
    string ignore_contents = ReadFileToString(IgnoreFile,
                                              /*die_if_failed*/true);
    ReadIgnoresFromString(ignore_contents, res);
  }
  return res;
}

// We use the 'ignore' machinery from ThreadSanitizer.
// See http://code.google.com/p/data-race-test/wiki/ThreadSanitizerIgnores
static bool WantToIgnoreFunction(Function &F) {
  // Thread-safe static initialization.
  // TODO(kcc): is this thread-safe on all clang/llvm platforms?
  static IgnoreLists *Ignores = ReadIgnores();

  if (TripleVectorMatchKnown(Ignores->ignores, F.getNameStr(), "", "")) {
    return true;
  }
  return false;
}

bool AddressSanitizer::handleFunction(Function &F) {
  if (WantToIgnoreFunction(F)) return false;

  if (!ClDebugFunc.empty() && ClDebugFunc != F.getNameStr())
    return false;


  if (TD->getPointerSize() == 4) {
    // For 32-bit arch the mapping is always compact.
    ClByteToByteShadow = false;
  }

  // Fill the set of memory operations to instrument.
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    for (BasicBlock::iterator BI = FI->begin(), BE = FI->end();
         BI != BE; ++BI) {
      if ((isa<LoadInst>(BI) && ClInstrumentReads) ||
          (isa<StoreInst>(BI) && ClInstrumentWrites)) {
        to_instrument.insert(BI);
      }

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
        if (func && func->getNameStr() == "llvm.eh.exception")
          return false;
      }
    }
  }

  // Instrument.
  int n_instrumented = 0;
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    BasicBlock &BB = *FI;
    for (BasicBlock::iterator BI = BB.begin(), BE = BB.end();
         BI != BE; ++BI) {
      if (!to_instrument.count(BI)) continue;
      // errs() << F.getNameStr() << (isa<StoreInst>(BI) ? " st" : " ld") << "\n";
      // Instrument LOAD or STORE.
      if (ClDebugMin < 0 || ClDebugMax < 0 ||
          (n_instrumented >= ClDebugMin && n_instrumented <= ClDebugMax))
        instrumentMop(BI);
      n_instrumented++;
      // BI is put into a separate block, so we need to stop processing this
      // one, making sure we don't instrument it twice.
      to_instrument.erase(BI);
      break;
    }
  }
  // errs() << "--------------------\n";
  if (!ClDebugFunc.empty())
    errs() << F;
  //
  //

  bool changed_stack = false;
  if (ClStack) {
    changed_stack = poisonStackInFunction(F);
  }

  return n_instrumented > 0 || changed_stack;
}

// given 64 aligned bytes, need to poison last 64-n bytes.
static uint64_t computeCompactPartialPoisonValue(int n) {
  union {
    uint64_t u64;
    uint8_t  u8[8];
  } a;
  CHECK(n > 0 && n < 64);
  for (int i = 0; i < 8; i++) {
    if (n > (i+1) * 8) {
      a.u8[i] = 0;
    } else if (n > i * 8){
      a.u8[i] = n % 8;
    } else {
      a.u8[i] = 0x90 + i;
    }
  }
  // Printf("computeCompactPartialPoisonValue: %d %llx\n", n, a.u64);
  return a.u64;
}


void AddressSanitizer::PoisonStack(SmallVector<AllocaInst*, 16> &alloca_v, IRBuilder<> irb,
                                   Value *shadow_base, bool do_poison) {

  Value *poison_all = ConstantInt::get(i64Ty, do_poison ? -1LL : 0LL);

  // poison the first red zone.
  irb.CreateStore(poison_all, irb.CreateIntToPtr(shadow_base, i64PtrTy));

  // poison all other red zones.
  uint64_t size_so_far = kAsanStackRedzone;
  for (size_t i = 0; i < alloca_v.size(); i++) {
    AllocaInst *a = alloca_v[i];
    uint64_t size_in_bytes = getAllocaSizeInBytes(a);
    uint64_t aligned_size = getAlignedAllocaSize(a);
    CHECK(aligned_size - size_in_bytes < kAsanStackAlignment);
    size_so_far += aligned_size;
    Value *ptr = irb.CreateAdd(
        shadow_base, ConstantInt::get(LongTy, size_so_far / 8));
    irb.CreateStore(poison_all, irb.CreateIntToPtr(ptr, i64PtrTy));
    if (size_in_bytes < aligned_size) {
      ptr = irb.CreateAdd(
          shadow_base, ConstantInt::get(LongTy, size_so_far / 8 - 8));
      size_t addressible_bytes = kAsanStackRedzone - (aligned_size - size_in_bytes);
      uint64_t poison = do_poison
          ? computeCompactPartialPoisonValue(addressible_bytes) : 0;
      Value *partial_poison = ConstantInt::get(i64Ty, poison);
      irb.CreateStore(partial_poison, irb.CreateIntToPtr(ptr, i64PtrTy));

    }
    size_so_far += kAsanStackRedzone;
  }

}

// Find all static Alloca instructions and put 
// poisoned red zones around all of them.
bool AddressSanitizer::poisonStackInFunction(Function &F) {
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
      if (!isa<AllocaInst>(BI)) continue;
      AllocaInst *a = cast<AllocaInst>(BI);
      if (a->isArrayAllocation()) continue;
      if (!a->isStaticAlloca()) continue;
      if (!a->getAllocatedType()->isSized()) continue;
      alloca_v.push_back(a);
      unsigned alignment  = a->getAlignment();
      CHECK(alignment <= kAsanStackAlignment);
      uint64_t aligned_size =  getAlignedAllocaSize(a);
      total_size += aligned_size;
    }
  }

  if (alloca_v.empty()) return false;

  uint64_t total_size_with_redzones =
      total_size + (alloca_v.size() + 1) * kAsanStackRedzone;

  // errs() << "total size w/ redzones: " << total_size_with_redzones << "\n";

  Type *ByteArrayTy = ArrayType::get(ByteTy, total_size_with_redzones);
  Instruction *ins_before = alloca_v[0];

  AllocaInst *my_alloca = new AllocaInst(ByteArrayTy, "my_alloca", ins_before);;
  my_alloca->setAlignment(kAsanStackAlignment);
  CHECK(my_alloca->isStaticAlloca());
  Value *base = new PtrToIntInst(my_alloca, LongTy, "local_base", ins_before);

  uint64_t size_so_far = kAsanStackRedzone;
  // Replace Alloca instructions with base+offset.
  for (size_t i = 0; i < alloca_v.size(); i++) {
    AllocaInst *a = alloca_v[i];
    uint64_t aligned_size = getAlignedAllocaSize(a);
    CHECK((aligned_size % kAsanStackAlignment) == 0);
    Value *new_ptr = BinaryOperator::CreateAdd(
        base, ConstantInt::get(LongTy, size_so_far), "", a);
    new_ptr = new IntToPtrInst(new_ptr, a->getType(), "", a);

    size_so_far += aligned_size + kAsanStackRedzone;
    a->replaceAllUsesWith(new_ptr);
  }
  CHECK(size_so_far == total_size_with_redzones);

  // Poison the stack redzones at the entry.
  IRBuilder<> irb(ins_before->getParent(), ins_before);
  Value *shadow_base = memToShadow(base, irb);
  PoisonStack(alloca_v, irb, shadow_base, true);

  // Unpoison the stack before all ret instructions.
  for (size_t i = 0; i < ret_v.size(); i++) {
    Instruction *ret = ret_v[i];
    IRBuilder<> irb_ret(ret->getParent(), ret);
    PoisonStack(alloca_v, irb_ret, shadow_base, false);
  }

  // errs() << F.getNameStr() << "\n" << F << "\n";
  return true;
}

// generate 0xabab... constant of appropriate size.
Value *AddressSanitizer::getPoisonConst(int size) {
  switch (size) {
    case 8:  return ConstantInt::get(Type::getIntNTy(*Context, size), kInMemoryPoison8);
    case 16: return ConstantInt::get(Type::getIntNTy(*Context, size), kInMemoryPoison16);
    case 32: return ConstantInt::get(Type::getIntNTy(*Context, size), kInMemoryPoison32);
    case 64: return ConstantInt::get(Type::getIntNTy(*Context, size), kInMemoryPoison64);
    default: assert(0); return 0;
  }
}

// Instrumentation for the in-memory poisoning. Does not really work yet.
void AddressSanitizer::instrumentInMemoryLoad(
    BasicBlock::iterator &BI, 
    Value *load,
    Value *Addr, int size, int telltale_value) {
  assert(isa<LoadInst>(load));
  BasicBlock *bb1 = BI->getParent();
  BasicBlock *bbT = bb1->splitBasicBlock(BI, "bbT_");
  BasicBlock *bb2 = bb1->splitBasicBlock(bb1->getTerminator(), "bb2_");
  BasicBlock *bb3 = bb2->splitBasicBlock(bb2->getTerminator(), "bb3_");
  BasicBlock *bb4 = bb3->splitBasicBlock(bb3->getTerminator(), "bb4_");

  /*      b1
  //      |\
  //      | \
  //      |  b2
  //      |  | \
  //      |  |  \
  //      |  |   \
  //      |  b3---b4
  //      | /
  //      T */

  IRBuilder<> irb1(bb1->getTerminator());
  if (load->getType()->isPointerTy())
    load = irb1.CreatePtrToInt(load, LongTy);
  Value *SizedPoison = getPoisonConst(size);
  assert (load->getType() == SizedPoison->getType());
  Value *cmp1 = irb1.CreateICmpEQ(load, SizedPoison);
  BranchInst *term1 = BranchInst::Create(bb2, bbT, cmp1);
  ReplaceInstWithInst(bb1->getTerminator(), term1);

  IRBuilder<> irb2(bb2->getTerminator());
  Value *LongPoison = getPoisonConst(LongSize);
  Value *Offset = ConstantInt::get(LongTy, LongSize / 8);
  Value *AddrLong = irb2.CreatePointerCast(Addr, LongTy);
  Value *LeftAddr = irb2.CreateIntToPtr(irb2.CreateSub(AddrLong, Offset), LongPtrTy);
  Value *LeftLoad = irb2.CreateLoad(LeftAddr);
  Value *cmp2 = irb2.CreateICmpEQ(LeftLoad, LongPoison);
  BranchInst *term2 = BranchInst::Create(bb4, bb3, cmp2);
  ReplaceInstWithInst(bb2->getTerminator(), term2);

  IRBuilder<> irb3(bb3->getTerminator());
  Value *RightAddr = irb3.CreateIntToPtr(irb3.CreateAdd(AddrLong, Offset), LongPtrTy);
  Value *RightLoad = irb3.CreateLoad(RightAddr);
  Value *cmp3 = irb3.CreateICmpEQ(RightLoad, LongPoison);
  BranchInst *term3 = BranchInst::Create(bb4, bbT, cmp3);
  ReplaceInstWithInst(bb3->getTerminator(), term3);
  
  IRBuilder<> irb4(bb4->getTerminator());
  irb4.CreateCall2(asan_slow_path, AddrLong, ConstantInt::get(LongTy, telltale_value));
}
