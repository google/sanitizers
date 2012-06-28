// AddressSanitizer - PIN.
#include "pin.H"
#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdlib.h>

#include "msan.h"

static bool inited;

typedef void (*void_F_void)(void);
static void_F_void msan_clear_on_return = 0;

static void AfterMsanInit() {
//  if (!inited)
//    fprintf(stderr, "AfterMsanInit\n");
  inited = true;
}

static long long dummy_tls[1000];
static long long *tls_p[PIN_MAX_THREADS];

static void MsanClear(ADDRINT addr, THREADID tid) {
  tls_p[tid] = (long long*)addr;
  // fprintf(stderr, "MsanClear addr %p id %d\n", (void*)addr, tid);
}

static void access16(uintptr_t addr) {
  uint64_t *p = (uint64_t*)MEM_TO_SHADOW(addr);
  p[0] = 0;
  p[1] = 0;
}
static void access8(uintptr_t addr) {
  uint64_t *p = (uint64_t*)MEM_TO_SHADOW(addr);
  *p = 0;
}
static void access4(uintptr_t addr) {
  uint32_t *p = (uint32_t*)MEM_TO_SHADOW(addr);
  *p = 0;
}
static void access2(uintptr_t addr) {
  uint16_t *p = (uint16_t*)MEM_TO_SHADOW(addr);
  *p = 0;
}
static void access1(uintptr_t addr) {
  uint8_t *p = (uint8_t*)MEM_TO_SHADOW(addr);
  *p = 0;
}

static void on_ret(THREADID tid)  {
  long long *p = tls_p[tid];
  p[0] = 0;
  p[1] = 0;
  p[2] = 0;
  p[4] = 0;
}

void CallbackForTRACE(TRACE trace, void *v) {
  RTN rtn = TRACE_Rtn(trace);
  if (!RTN_Valid(rtn)) return;
  string rtn_name = RTN_Name(rtn);
  string img_name = IMG_Name(SEC_Img(RTN_Sec(rtn)));

  if (img_name.find("pintest_so.so") == string::npos &&
      img_name.find("/usr/lib/") != 0 &&
      img_name.find("/lib/") != 0)
    return;
  // printf("rtn: %s %s\n", rtn_name.c_str(), img_name.c_str());
  // string *info = new string (rtn_name + " (" + img_name + ")");

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      int n_mops = INS_MemoryOperandCount(ins);
      for (int i = 0; i < n_mops; i++) {
        if (!INS_MemoryOperandIsWritten(ins, i)) continue;
        size_t size = INS_MemoryOperandSize(ins, i);
        void (*callback)(uintptr_t) = 0;
        if (size == 1)  callback = access1;
        if (size == 2)  callback = access2;
        if (size == 4)  callback = access4;
        if (size == 8)  callback = access8;
        if (size == 16) callback = access16;
        assert(callback);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callback,
                       IARG_MEMORYOP_EA, i, IARG_END);
      }
      if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)on_ret,
                       IARG_THREAD_ID,
                       IARG_END);
      }
    }
  }
}

void CallbackForIMG(IMG img, void *v) {
  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
      string rtn_name = RTN_Name(rtn);
      // if (rtn_name == #name) { name = (AsanReportCallback)RTN_Address(rtn); }
      if (rtn_name == "__msan_clear_on_return") {
        msan_clear_on_return = (void_F_void)RTN_Address(rtn);
        // fprintf(stderr, "msan_clear_on_return: %p\n", msan_clear_on_return);
        RTN_Open(rtn);
        INS ins = RTN_InsHead(rtn);
        assert(ins != INS_Invalid());
        // fprintf(stderr, "zzz %s\n", INS_Mnemonic(ins).c_str());
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)MsanClear,
                       IARG_MEMORYOP_EA, 0,
                       IARG_THREAD_ID,
                       IARG_END);
        RTN_Close(rtn);
      }
      if (rtn_name == "__msan_init") {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_AFTER, AfterMsanInit, IARG_END);
        RTN_Close(rtn);
      }
    }
  }
}
#include "msan_linux_inl.h"

int main(INT32 argc, CHAR **argv) {
  for (size_t i =0; i < PIN_MAX_THREADS; i++)
    tls_p[i] = dummy_tls;

  __msan::InitShadow(false, true, true);
  PIN_Init(argc, argv);
  PIN_InitSymbols();
  IMG_AddInstrumentFunction(CallbackForIMG, 0);
  TRACE_AddInstrumentFunction(CallbackForTRACE, 0);
  PIN_StartProgram();
  return 0;
}

void Init() {
}
