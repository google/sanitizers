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
static cl::opt<bool> ClCall("asan-call",
       cl::desc("Use call instead of SEGV"), cl::init(false));
static cl::opt<bool> ClByteToByteShadow("asan-byte-to-byte-shadow",
       cl::desc("Use full (byte-to-byte) shadow mapping"), cl::init(false));
static cl::opt<bool>  ClCrOS("asan-cros",
       cl::desc("Instrument for 32-bit ChromeOS"), cl::init(false));
static cl::opt<string>  IgnoreFile("asan-ignore",
       cl::desc("File containing the list of functions to ignore "
                        "during instrumentation"));

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
struct AddressSanitizer : public ModulePass {
  AddressSanitizer();
  void instrumentMop(BasicBlock::iterator &BI);
  void instrumentInMemoryLoad(BasicBlock::iterator &BI, Value *load, Value *Addr, int size, int teltale);
  Value *getPoisonConst(int size);
  bool handleFunction(Function &F);
  virtual bool runOnModule(Module &M);
  BranchInst *splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *cmp);
  static char ID; // Pass identification, replacement for typeid
 private:
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
  const Type *BytePtrTy;
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
  if (ClCall) {
    irb4.CreateCall2(asan_slow_path, AddrLong, ConstantInt::get(LongTy, telltale_value));
  } else {
    irb4.CreateStore(AddrLong, asan_addr);
    irb4.CreateStore(ConstantInt::get(ByteTy, telltale_value), asan_aux);
    // FunctionType *FnTy = FunctionType::get(VoidTy, false);
    // Value *int3_asm = InlineAsm::get(FnTy, StringRef("int3"), StringRef(""), true);
    // irb4.CreateCall(int3_asm);
    // Generates ud2
    Value *null_int = ConstantInt::get(LongTy, 0);
    Value *null_ptr = irb4.CreateIntToPtr(null_int, LongPtrTy);
    irb4.CreateStore(null_int, null_ptr);
  }
}

void AddressSanitizer::instrumentMop(BasicBlock::iterator &BI) {
  Instruction *mop = BI;
  int is_store = !!isa<StoreInst>(*mop);
  Value *Addr = is_store
      ? cast<StoreInst>(*mop).getPointerOperand()
      : cast<LoadInst>(*mop).getPointerOperand();
  const Type *OrigPtrTy = Addr->getType();
  const Type *OrigType = cast<PointerType>(OrigPtrTy)->getElementType();
  bool in_mem_needs_extra_load = isa<StoreInst>(*mop);

  unsigned type_size = 0;  // in bits
  if (OrigType->isSized()) {
    type_size = TD->getTypeStoreSizeInBits(OrigType);
  } else {
    errs() << "Type " << *OrigType << " has unknown size!\n";
    assert(false);
  }

  if (type_size != 8  && type_size != 16
      && type_size != 32 && type_size != 64) {
    // TODO(kcc): do something better.
    return;
  }

  uint8_t telltale_value = is_store * 16 + (type_size / 8);

  if (!(OrigType->isIntOrIntVectorTy() || OrigType->isPointerTy()) ||
      TD->getTypeSizeInBits(OrigType) != type_size) {
    // This type is unsupported by the ICMP instruction. Cast it to the int of
    // appropriate size.
    OrigType = IntegerType::get(*Context, type_size);
    OrigPtrTy = PointerType::get(OrigType, 0);
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
  Value *Shadow = AddrLong;

  Value *ShadowPtr = NULL;
  Value *CmpVal;
  if (!ClByteToByteShadow) {
    Shadow = irb1.CreateLShr(Shadow, 3);
    uint64_t mask = TD->getPointerSize() == 4
        ? (ClCrOS ? kCROSShadowMask32 : kCompactShadowMask32)
        : kCompactShadowMask64;
    Shadow = irb1.CreateOr(Shadow, ConstantInt::get(LongTy, mask));
    ShadowPtr = irb1.CreateIntToPtr(Shadow, BytePtrTy);
    CmpVal = ConstantInt::get(ByteTy, 0);
  } else {
    // Shadow |= kFullLowShadowMask
    Shadow = irb1.CreateOr(
        Shadow, ConstantInt::get(LongTy, kFullLowShadowMask));
    // Shadow &= ~kFullHighShadowMask
    Shadow = irb1.CreateAnd(
        Shadow, ConstantInt::get(LongTy, ~kFullHighShadowMask));
    // ShadowPadded = Shadow + kBankPadding;
    Value *ShadowPadded = irb1.CreateAdd(
        Shadow, ConstantInt::get(LongTy, kBankPadding));

    ShadowPtr = irb1.CreateIntToPtr(ShadowPadded, OrigPtrTy);
    CmpVal = Constant::getNullValue(OrigType);
  }
  Value *ShadowValue = irb1.CreateLoad(ShadowPtr);
  // If the shadow value is non-zero, write to the check address, else
  // continue executing the old code.
  Value *Cmp = irb1.CreateICmpNE(ShadowValue, CmpVal);
  // Split the mop and the successive code into a separate block.
  // Note that it invalidates the iterators used in handleFunction(),
  // but we're ok with that as long as we break from the loop immediately
  // after insrtumentMop().

  Instruction *CheckTerm = splitBlockAndInsertIfThen(BI, Cmp);
  IRBuilder<> irb2(CheckTerm->getParent(), CheckTerm);

  Value *UpdateShadowIntPtr = irb2.CreateShl(Shadow, ClCrOS ? 2 : 1);
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

  if (ClCall) {
    irb3.CreateCall2(asan_slow_path, AddrLong, ConstantInt::get(LongTy, telltale_value));
  } else {
    if (!ClByteToByteShadow) {
      Value *ShadowLongPtr = irb3.CreateIntToPtr(Shadow, LongPtrTy);
      irb3.CreateStore(AddrLong, ShadowLongPtr);
    }
    Value *TellTale = ConstantInt::get(ByteTy, telltale_value);
    Instruction *CheckStoreInst = irb3.CreateStore(TellTale, CheckPtr);
    CloneDebugInfo(mop, CheckStoreInst);
  }
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
  ByteTy  = Type::getInt8Ty(*Context);
  BytePtrTy = PointerType::get(ByteTy, 0);
  LongPtrTy = PointerType::get(LongTy, 0);
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
  if (ClCall)
    flag_value |= 1 << AsanFlagUseCall;
  else if (ClShadow) {
    flag_value |= 1 << AsanFlagUseSegv;
  } else {
    flag_value |= 1 << AsanFlagUseUd2;
  }

  new GlobalVariable(M, LongTy, /*isConstant*/true,
                     GlobalValue::WeakODRLinkage,
                     ConstantInt::get(LongTy, flag_value),
                     "__asan_flag",
                     0, false);

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
  //errs() << "============" << F.getNameStr() << "\n";


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
      instrumentMop(BI);
      n_instrumented++;
      // BI is put into a separate block, so we need to stop processing this
      // one, making sure we don't instrument it twice.
      to_instrument.erase(BI);
      break;
    }
  }
  //errs() << "--------------------\n";
  //errs() << F;
  return n_instrumented > 0;
}
