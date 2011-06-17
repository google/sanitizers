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

#define DEBUG_TYPE "asan"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
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
static cl::opt<bool> ClGlobals("asan-globals",
       cl::desc("Handle global objects"), cl::init(false));
static cl::opt<bool> ClMemIntrin("asan-memintrin",
       cl::desc("Handle memset/memcpy/memmove"), cl::init(true));
static cl::opt<string>  IgnoreFile("asan-ignore",
       cl::desc("File containing the list of functions to ignore "
                        "during instrumentation"));

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
static cl::opt<int> ClDebugStack("asan-debug-stack", cl::desc("debug stack"), cl::init(0));
static cl::opt<string> ClDebugFunc("asan-debug-func", cl::desc("Debug func"));
static cl::opt<int> ClDebugMin("asan-debug-min",
                               cl::desc("Debug min inst"), cl::init(-1));
static cl::opt<int> ClDebugMax("asan-debug-max",
                               cl::desc("Debug man inst"), cl::init(-1));

// Define the Printf function used by the ignore machinery.
void Printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  fflush(stderr);
  va_end(args);
}

namespace {

static const char *kAsanGlobalPoisonerName = "asan.poison_globals";

struct AddressSanitizer : public ModulePass {
  AddressSanitizer();
  void instrumentMop(BasicBlock::iterator &BI);
  void instrumentAddress(Instruction *orig_mop, IRBuilder<> &irb1,
                         Value *Addr, size_t type_size, bool is_w);
  bool instrumentMemIntrinsic(MemIntrinsic *mem_intr);
  void instrumentMemIntrinsicParam(Instruction *orig_mop, Value *addr, Value *size,
                                   Instruction *insert_before, bool is_w);
  Value *memToShadow(Value *Shadow, IRBuilder<> &irb);
  bool handleFunction(Function &F);
  bool poisonStackInFunction(Function &F);
  virtual bool runOnModule(Module &M);
  bool insertGlobalRedzones(Module &M);
  void appendToGlobalCtors(Module &M, Function *f);
  BranchInst *splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *cmp);
  static char ID; // Pass identification, replacement for typeid

 private:

  uint64_t getAllocaSizeInBytes(AllocaInst *a) {
    const Type *ty = a->getAllocatedType();
    uint64_t size_in_bytes = TD->getTypeStoreSizeInBits(ty) / 8;
    return size_in_bytes;
  }
  uint64_t getAlignedSize(uint64_t size_in_bytes) {
    return ((size_in_bytes + kAsanRedzone - 1)
            / kAsanRedzone) * kAsanRedzone;
  }
  uint64_t getAlignedAllocaSize(AllocaInst *a) {
    uint64_t size_in_bytes = getAllocaSizeInBytes(a);
    return getAlignedSize(size_in_bytes);
  }

  void PoisonStack(const ArrayRef<AllocaInst*> &alloca_v, IRBuilder<> irb,
                   Value *shadow_base, bool do_poison);

  LLVMContext *C;
  TargetData *TD;
  int         LongSize;
  const Type *VoidTy;
  const Type *LongTy;
  const Type *LongPtrTy;
  const Type *i32Ty;
  const Type *i32PtrTy;
  const Type *ByteTy;
  const Type *BytePtrTy;
  SmallSet<Instruction*, 16> to_instrument;
};
}  // namespace

char AddressSanitizer::ID = 0;
INITIALIZE_PASS(AddressSanitizer, "asan",
    "AddressSanitizer: detects use-after-free and out-of-bounds bugs.", false, false)
AddressSanitizer::AddressSanitizer() : ModulePass(ID) { }
ModulePass *llvm::createAddressSanitizerPass() {
  return new AddressSanitizer();
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
BranchInst *AddressSanitizer::splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *Cmp) {
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
  // Shadow >> 3
  Shadow = irb.CreateLShr(Shadow, 3);
  uint64_t mask = TD->getPointerSize() == 4
      ? kCompactShadowMask32
      : kCompactShadowMask64;
  // (Shadow >> 3) | mask
  return irb.CreateOr(Shadow, ConstantInt::get(LongTy, mask));
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


void AddressSanitizer::instrumentMop(BasicBlock::iterator &BI) {
  Instruction *mop = BI;
  int is_w = !!isa<StoreInst>(*mop);
  Value *Addr = getLDSTOperand(mop);
  if (ClOpt && ClOptGlobals && isa<GlobalVariable>(Addr)) {
    // We are accessing a global scalar variable. Nothing to catch here.
    return;
  }
  const Type *OrigPtrTy = Addr->getType();
  const Type *OrigTy = cast<PointerType>(OrigPtrTy)->getElementType();

  assert(OrigTy->isSized());
  unsigned type_size = TD->getTypeStoreSizeInBits(OrigTy);

  if (type_size != 8  && type_size != 16
      && type_size != 32 && type_size != 64 && type_size != 128) {
    // TODO(kcc): do something better.
    return;
  }

  IRBuilder<> irb1(BI->getParent(), BI);
  instrumentAddress(mop, irb1, Addr, type_size, is_w);
}

void AddressSanitizer::instrumentAddress(Instruction *orig_mop, IRBuilder<> &irb1, Value *Addr,
                                         size_t type_size, bool is_w) {
  unsigned log_of_size_in_bytes = __builtin_ctz(type_size / 8);
  assert(8U * (1 << log_of_size_in_bytes) == type_size);
  uint8_t telltale_value = is_w * 8 + log_of_size_in_bytes;
  assert(telltale_value < 16);


  Value *AddrLong = irb1.CreatePointerCast(Addr, LongTy);

  const Type *ShadowTy  = IntegerType::get(
      *C, max((size_t)8, type_size / 8));
  const Type *ShadowPtrTy = PointerType::get(ShadowTy, 0);
  Value *ShadowPtr = memToShadow(AddrLong, irb1);
  Value *CmpVal = Constant::getNullValue(ShadowTy);
  Value *ShadowValue = irb1.CreateLoad(
      irb1.CreateIntToPtr(ShadowPtr, ShadowPtrTy));
  // If the shadow value is non-zero, write to the check address, else
  // continue executing the old code.
  Value *Cmp = irb1.CreateICmpNE(ShadowValue, CmpVal);
  // Split the mop and the successive code into a separate block.
  // Note that it invalidates the iterators used in handleFunction(),
  // but we're ok with that as long as we break from the loop immediately
  // after insrtumentMop().

  Instruction *CheckTerm = splitBlockAndInsertIfThen(
      cast<Instruction>(Cmp)->getNextNode(), Cmp);
  IRBuilder<> irb2(CheckTerm->getParent(), CheckTerm);

  if (type_size < 64) {
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

  // Move the failing address to %rax/%eax
  FunctionType *Fn1Ty = FunctionType::get(
      VoidTy, ArrayRef<const Type*>(LongTy), false);
  const char *mov_str = LongSize == 32
      ? "mov $0, %eax" : "mov $0, %rax";
  Value *asm_mov = InlineAsm::get(
      Fn1Ty, StringRef(mov_str), StringRef("r"), true);
  irb3.CreateCall(asm_mov, AddrLong);

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

  FunctionType *Fn0Ty = FunctionType::get(VoidTy, false);
  std::string asm_str = "ud2;";
  asm_str += telltale_insns[telltale_value];
  Value *my_asm = InlineAsm::get(Fn0Ty, StringRef(asm_str), StringRef(""), true);
  CallInst *asm_call = irb3.CreateCall(my_asm);
  CloneDebugInfo(orig_mop, asm_call);

  // This saves us one jump, but triggers a bug in RA (or somewhere else):
  // while building 483.xalancbmk the compiler goes into infinite loop in
  // llvm::SpillPlacement::iterate() / RAGreedy::growRegion
  // asm_call->setDoesNotReturn();
}

// Append 'f' to the list of global ctors.
void AddressSanitizer::appendToGlobalCtors(Module &M, Function *f) {
  // The code is shamelessly stolen from
  // RegisterRuntimeInitializer::insertInitializerIntoGlobalCtorList().
  // LLVM may need a general API function for this.

  std::vector<Constant *> CtorInits;
  CtorInits.push_back (ConstantInt::get (i32Ty, 65535));
  CtorInits.push_back (f);
  Constant *RuntimeCtorInit = ConstantStruct::get(
      *C, CtorInits, false);

  // Get the current set of static global constructors and add the new ctor
  // to the list.
  std::vector<Constant *> CurrentCtors;
  GlobalVariable * GVCtor = M.getNamedGlobal ("llvm.global_ctors");
  if (GVCtor) {
    if (Constant * C = GVCtor->getInitializer()) {
      for (unsigned index = 0; index < C->getNumOperands(); ++index) {
        CurrentCtors.push_back (cast<Constant>(C->getOperand (index)));
      }
    }
    // Rename the global variable so that we can name our global
    // llvm.global_ctors.
    GVCtor->setName ("removed");
  }

  CurrentCtors.push_back(RuntimeCtorInit);

  // Create a new initializer.
  const ArrayType * AT = ArrayType::get (RuntimeCtorInit->getType(),
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

// ***unfinished***
// This function replaces all global variables with new variables that have
// leading and trailing redzones.
bool AddressSanitizer::insertGlobalRedzones(Module &M) {
  Module::GlobalListType &globals = M.getGlobalList();

  Type *LeftRedZoneTy = ArrayType::get(ByteTy, kAsanRedzone);

  // We will create a new function that poisons all readzones.
  Function *poisoner = NULL;
  Instruction *insert_before = 0;

  for (Module::GlobalListType::iterator G = globals.begin(),
       E = globals.end(); G != E; ++G) {
    GlobalVariable &orig_global = *G;
    const PointerType *ptrty = cast<PointerType>(orig_global.getType());
    const Type *ty = ptrty->getElementType();
    if (!ty->isSized()) continue;
    if (!orig_global.hasInitializer()) continue;
    if (orig_global.isConstant()) continue;  // do we care about constants?
    if (orig_global.getLinkage() != GlobalVariable::ExternalLinkage &&
        orig_global.getLinkage() != GlobalVariable::PrivateLinkage) {
      // do we care about other linkages?
      continue;
    }
    // TODO(kcc): do something smart if the alignment is large.

    uint64_t size_in_bytes = TD->getTypeStoreSizeInBits(ty) / 8;
    uint64_t right_redzone_size = kAsanRedzone +
        (kAsanRedzone - (size_in_bytes % kAsanRedzone));
    Type *RightRedZoneTy = ArrayType::get(ByteTy, right_redzone_size);

    const Type *new_ty = StructType::get(
        *C, LeftRedZoneTy, ty, RightRedZoneTy, NULL);
    Constant *new_initializer = ConstantStruct::get(
        *C, /*packed=*/false,
        Constant::getNullValue(LeftRedZoneTy),
        orig_global.getInitializer(),
        Constant::getNullValue(RightRedZoneTy),
        NULL);

    // Create a new global variable with enough space for a redzone.
    GlobalVariable *new_global = new GlobalVariable(
        M, new_ty, orig_global.isConstant(), orig_global.getLinkage(),
        new_initializer,
        orig_global.getName() + "_asan_redzone",
        &orig_global, orig_global.isThreadLocal());
    new_global->copyAttributesFrom(&orig_global);

    // Q: We need to poison the shadow values corresponding to redzones.
    // Not redzones themselves (their values are irrelevant), but the
    // memory starting from ((redzone_addr >> 3) + offset).
    // One way is to create a new function with attribute constructor
    // and construct the function body such that it poisons the redzones.
    // Is there a simpler way?

    Constant *Indices[2];
    Indices[0] = ConstantInt::get(i32Ty, 0);
    Indices[1] = ConstantInt::get(i32Ty, 1);
    GlobalAlias *alias = new GlobalAlias(
        ptrty, GlobalValue::ExternalLinkage, "",
        ConstantExpr::getGetElementPtr(new_global, Indices, 2),
        new_global->getParent());

    orig_global.replaceAllUsesWith(alias);
    alias->takeName(&orig_global);

    if (!poisoner) {
      FunctionType *Fn0Ty = FunctionType::get(VoidTy, false);
      poisoner = Function::Create(Fn0Ty, GlobalValue::PrivateLinkage,
                                  kAsanGlobalPoisonerName,
                                  &M);
      BasicBlock *bb = BasicBlock::Create(*C, "", poisoner);
      insert_before = ReturnInst::Create(*C, bb);
    }

    IRBuilder<> irb(insert_before->getParent(), insert_before);
    Value *asan_register_global = M.getOrInsertFunction(
        "__asan_register_global", VoidTy, LongTy, LongTy, NULL);
    irb.CreateCall2(asan_register_global,
                   irb.CreatePointerCast(new_global, LongTy),
                   ConstantInt::get(LongTy, size_in_bytes));

    if (ClDebug) {
      errs() << "GLOBAL: " << orig_global;
      errs() << "   " <<  *ty << " --- " << *new_ty << "\n";
      errs() << *new_initializer << "\n";
      errs() << *new_global << "\n";
      errs() << *alias << "\n";
    }
  }


  if (poisoner) {
    appendToGlobalCtors(M, poisoner);
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
  C = &(M.getContext());
  LongSize = TD->getPointerSizeInBits();
  LongTy = Type::getIntNTy(*C, LongSize);
  i32Ty = Type::getIntNTy(*C, 32);
  ByteTy  = Type::getInt8Ty(*C);
  BytePtrTy = PointerType::get(ByteTy, 0);
  LongPtrTy = PointerType::get(LongTy, 0);
  i32PtrTy = PointerType::get(i32Ty, 0);
  VoidTy = Type::getVoidTy(*C);

  bool res = false;

  if (ClGlobals)
    res |= insertGlobalRedzones(M);

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

bool AddressSanitizer::handleFunction(Function &F) {
  if (WantToIgnoreFunction(F)) return false;
  if (F.getNameStr() == kAsanGlobalPoisonerName) return false;

  if (!ClDebugFunc.empty() && ClDebugFunc != F.getNameStr())
    return false;

  // We want to instrument every address only once per basic block
  // (unless there are calls between uses).
  SmallSet<Value*, 16> temps_to_instrument;

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
      to_instrument.insert(BI);
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
          (n_instrumented >= ClDebugMin && n_instrumented <= ClDebugMax)) {
        if (isa<StoreInst>(BI) || isa<LoadInst>(BI))
          instrumentMop(BI);
        else
          instrumentMemIntrinsic(cast<MemIntrinsic>(BI));
      }
      n_instrumented++;
      // BI is put into a separate block, so we need to stop processing this
      // one, making sure we don't instrument it twice.
      to_instrument.erase(BI);
      break;
    }
  }
  // errs() << "--------------------\n";
  if (!ClDebugFunc.empty() || ClDebug)
    errs() << F;
  //
  //

  bool changed_stack = false;
  if (ClStack) {
    changed_stack = poisonStackInFunction(F);
    if (changed_stack && ClDebugStack)
      errs() << F;
  }

  return n_instrumented > 0 || changed_stack;
}


void AddressSanitizer::PoisonStack(const ArrayRef<AllocaInst*> &alloca_v, IRBuilder<> irb,
                                   Value *shadow_base, bool do_poison) {

  Value *poison_left  = ConstantInt::get(i32Ty, do_poison ? 0xf1f2f3f4 : 0LL);
  Value *poison_mid   = ConstantInt::get(i32Ty, do_poison ? 0xf5f6f7f8 : 0LL);
  Value *poison_right = ConstantInt::get(i32Ty, do_poison ? 0xfafbfcfd : 0LL);

  // poison the first red zone.
  irb.CreateStore(poison_left, irb.CreateIntToPtr(shadow_base, i32PtrTy));

  // poison all other red zones.
  uint64_t pos = kAsanRedzone;
  for (size_t i = 0; i < alloca_v.size(); i++) {
    AllocaInst *a = alloca_v[i];
    uint64_t size_in_bytes = getAllocaSizeInBytes(a);
    uint64_t aligned_size = getAlignedAllocaSize(a);
    CHECK(aligned_size - size_in_bytes < kAsanRedzone);
    Value *ptr;

    pos += aligned_size;

    if (size_in_bytes < aligned_size) {
      // Poison the partial redzone at right
      ptr = irb.CreateAdd(
          shadow_base, ConstantInt::get(LongTy, pos / 8 - 4));
      size_t addressible_bytes = kAsanRedzone - (aligned_size - size_in_bytes);
      uint64_t poison = do_poison
          ? kPartialRedzonePoisonValues[addressible_bytes] : 0;
      Value *partial_poison = ConstantInt::get(i32Ty, poison);
      irb.CreateStore(partial_poison, irb.CreateIntToPtr(ptr, i32PtrTy));
    }

    // Poison the full redzone at right.
    ptr = irb.CreateAdd(shadow_base, ConstantInt::get(LongTy, pos / 8));
    Value *poison = i == alloca_v.size() - 1 ? poison_right : poison_mid;
    irb.CreateStore(poison, irb.CreateIntToPtr(ptr, i32PtrTy));

    pos += kAsanRedzone;
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

      AllocaInst *a = dyn_cast<AllocaInst>(BI);
      if (!a) continue;
      if (a->isArrayAllocation()) continue;
      if (!a->isStaticAlloca()) continue;
      if (!a->getAllocatedType()->isSized()) continue;
      alloca_v.push_back(a);
      unsigned alignment  = a->getAlignment();
      CHECK(alignment <= kAsanRedzone);
      uint64_t aligned_size =  getAlignedAllocaSize(a);
      total_size += aligned_size;
    }
  }

  if (alloca_v.empty()) return false;

  uint64_t total_size_with_redzones =
      total_size + (alloca_v.size() + 1) * kAsanRedzone;

  // errs() << "total size w/ redzones: " << total_size_with_redzones << "\n";

  Type *ByteArrayTy = ArrayType::get(ByteTy, total_size_with_redzones);
  Instruction *ins_before = alloca_v[0];

  AllocaInst *my_alloca = new AllocaInst(ByteArrayTy, "my_alloca", ins_before);
  my_alloca->setAlignment(kAsanRedzone);
  CHECK(my_alloca->isStaticAlloca());
  Value *base = new PtrToIntInst(my_alloca, LongTy, "local_base", ins_before);

  uint64_t pos = kAsanRedzone;
  // Replace Alloca instructions with base+offset.
  for (size_t i = 0; i < alloca_v.size(); i++) {
    AllocaInst *a = alloca_v[i];
    uint64_t aligned_size = getAlignedAllocaSize(a);
    CHECK((aligned_size % kAsanRedzone) == 0);
    Value *new_ptr = BinaryOperator::CreateAdd(
        base, ConstantInt::get(LongTy, pos), "", a);
    new_ptr = new IntToPtrInst(new_ptr, a->getType(), "", a);

    pos += aligned_size + kAsanRedzone;
    a->replaceAllUsesWith(new_ptr);
  }
  CHECK(pos == total_size_with_redzones);

  // Poison the stack redzones at the entry.
  IRBuilder<> irb(ins_before->getParent(), ins_before);
  Value *shadow_base = memToShadow(base, irb);
  PoisonStack(ArrayRef<AllocaInst*>(alloca_v), irb, shadow_base, true);

  // Unpoison the stack before all ret instructions.
  for (size_t i = 0; i < ret_v.size(); i++) {
    Instruction *ret = ret_v[i];
    IRBuilder<> irb_ret(ret->getParent(), ret);
    PoisonStack(ArrayRef<AllocaInst*>(alloca_v), irb_ret, shadow_base, false);
  }

  // errs() << F.getNameStr() << "\n" << F << "\n";
  return true;
}
