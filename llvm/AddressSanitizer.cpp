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
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Type.h"

#include <stdint.h>
#include <stdio.h>

#include "ignore.h"

#include "asan_rtl.h"

#include <map>
using namespace llvm;
using namespace std;

// Command-line flags. {{{1
static cl::opt<bool>
    ClInstrumentReads("instrument-reads",
        cl::desc("TODO(glider)"),
        cl::init(true));
static cl::opt<bool>
    ClCompactShadow("compact-shadow",
        cl::desc("TODO(kcc)"),
        cl::init(false));
static cl::opt<bool>
    ClInstrumentWrites("instrument-writes",
        cl::desc("TODO(glider)"),
        cl::init(true));
static cl::opt<bool>
    Clm32("m32",
        cl::desc("m32"),
        cl::init(false));
static cl::opt<bool>
    ClCrOS("cros",
        cl::desc("CrOS"),
        cl::init(false));
static cl::opt<string>
    IgnoreFile("ignore",
               cl::desc("File containing the list of functions to ignore "
                        "during instrumentation"));

// }}}

namespace {

struct AddresSanitizer : public FunctionPass {
  AddresSanitizer();
  void instrumentMop(BasicBlock::iterator &BI);
  virtual bool runOnFunction(Function &F);
  Instruction *splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *cmp);
  static char ID; // Pass identification, replacement for typeid
 private:
  LLVMContext *Context;
  TargetData *TD;
  const Type *LongTy;
  const Type *LongPtrTy;
  const Type *ByteTy;
  const Type *BytePtrTy;
  SmallSet<Instruction*, 16> to_instrument;
};

AddresSanitizer::AddresSanitizer() : FunctionPass(&ID) {
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
Instruction *AddresSanitizer::splitBlockAndInsertIfThen(Instruction *SplitBefore, Value *Cmp) {
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

void AddresSanitizer::instrumentMop(BasicBlock::iterator &BI) {
  Instruction *mop = BI;
  Value *Addr = isa<StoreInst>(*mop)
      ? cast<StoreInst>(*mop).getPointerOperand()
      : cast<LoadInst>(*mop).getPointerOperand();
  const Type *OrigPtrTy = Addr->getType();
  const Type *OrigType = cast<PointerType>(OrigPtrTy)->getElementType();

  int type_size = 0;  // in bits
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

  if (!(OrigType->isIntOrIntVectorTy() || OrigType->isPointerTy())) {
    // This type is unsupported by the ICMP instruction. Cast it to the int of
    // appropriate size.
    OrigType = IntegerType::get(*Context, type_size);
    OrigPtrTy = PointerType::get(OrigType, 0);
  }

  IRBuilder<> irb1(BI->getParent(), BI);

  Value *AddrLong = irb1.CreatePointerCast(Addr, LongTy);
  Value *Shadow = AddrLong;

  Value *ShadowPtr = NULL;
  Value *CmpVal;
  if (Clm32 || ClCompactShadow) {
    Shadow = irb1.CreateLShr(Shadow, 3);
    uint64_t mask = Clm32
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
  // Note that it invalidates the iterators used in runOnFunction(),
  // but we're ok with that as long as we break from the loop immediately
  // after insrtumentMop().

  Instruction *CheckTerm = splitBlockAndInsertIfThen(BI, Cmp);

  Value *UpdateShadowIntPtr = BinaryOperator::CreateShl(
      Shadow, ConstantInt::get(LongTy, ClCrOS ? 2 : 1), "", CheckTerm);
  Value *CheckPtr =
      new IntToPtrInst(UpdateShadowIntPtr, BytePtrTy, "", CheckTerm);

  if (Clm32 || ClCompactShadow) {
    if (type_size != 64) {
      // addr & 7
      Value *Lower3Bits = BinaryOperator::CreateAnd(
          AddrLong, ConstantInt::get(LongTy, 7), "", CheckTerm);
      // (addr & 7) + size
      Value *LastAccessedByte = BinaryOperator::CreateAdd(
          Lower3Bits, ConstantInt::get(LongTy, type_size / 8), "", CheckTerm);
      // (uint8_t) ((addr & 7) + size)
      LastAccessedByte = BitCastInst::CreateIntegerCast(
          LastAccessedByte, ByteTy, false, "", CheckTerm);
      // ((uint8_t) ((addr & 7) + size)) > ShadowValue
      Value *cmp2 = new ICmpInst(
          CheckTerm, ICmpInst::ICMP_SGT, LastAccessedByte, ShadowValue);

      CheckTerm = splitBlockAndInsertIfThen(CheckTerm, cmp2);
    }

    Value *ShadowLongPtr = new IntToPtrInst(Shadow, LongPtrTy, "", CheckTerm);
    new StoreInst(AddrLong, ShadowLongPtr, "", CheckTerm);
  }
  uint8_t telltale_value = isa<StoreInst>(*mop) * 16 + (type_size / 8);
  Value *TellTale = ConstantInt::get(ByteTy, telltale_value);
  Instruction *CheckStoreInst = new StoreInst(TellTale, CheckPtr, "", CheckTerm);
  CloneDebugInfo(mop, CheckStoreInst);
}

// ----- ignores. TODO(kcc): clean this up -------
static IgnoreLists Ignores;
void ParseIgnoreFile(string &file) {
  string ignore_contents = ReadFileToString(file, /*die_if_failed*/true);
  ReadIgnoresFromString(ignore_contents, &Ignores);
}

// -------------- end ignores ------------------

// virtual
bool AddresSanitizer::runOnFunction(Function &F) {
  static bool ignores_inited;
  if (ignores_inited == false) {
    ignores_inited = true;
    if (IgnoreFile.size()) {
      ParseIgnoreFile(IgnoreFile);
    }
  }

  if (TripleVectorMatchKnown(Ignores.ignores, F.getNameStr(), "", "")) {
    return false;  // Nothing changed.
  }

  TD = getAnalysisIfAvailable<TargetData>();
  if (!TD)
    return false;

  // Initialize the private fields. No one has accessed them before.
  Context = &(F.getContext());
  LongTy = Clm32 ? Type::getInt32Ty(*Context)
                 : Type::getInt64Ty(*Context);
  ByteTy  = Type::getInt8Ty(*Context);
  BytePtrTy = PointerType::get(ByteTy, 0);
  LongPtrTy = PointerType::get(LongTy, 0);

  // Fill the set of memory operations to instrument.
  for (Function::iterator FI = F.begin(), FE = F.end();
       FI != FE; ++FI) {
    for (BasicBlock::iterator BI = FI->begin(), BE = FI->end();
         BI != BE; ++BI) {
      if ((isa<LoadInst>(BI) && ClInstrumentReads) ||
          isa<StoreInst>(BI) && ClInstrumentWrites) {
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
      // Instrument LOAD or STORE.
      instrumentMop(BI);
      n_instrumented++;
      // BI is put into a separate block, so we need to stop processing this
      // one, making sure we don't instrument it twice.
      to_instrument.erase(BI);
      break;
    }
  }
  return n_instrumented > 0;
}
}  // namespace

char AddresSanitizer::ID = 0;
RegisterPass<AddresSanitizer> X("asan",
    "AddressSanitizer: detects use-after-free and out-of-bounds bugs.");
