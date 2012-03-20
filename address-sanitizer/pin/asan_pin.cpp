// AddressSanitizer - PIN.
#include "pin.H"
#include <stdio.h>

inline uintptr_t MemToShadow(uintptr_t addr) {
  return (addr >> 3) + 0x0000100000000000ULL;
}

static bool inited;
void AfterAsanInit() {
  // fprintf(stderr, "AfterAsanInit\n");
  inited = true;
}

static uintptr_t access16_if(uintptr_t addr) {
  return inited ? *(uint16_t*)MemToShadow(addr) : 0;
}
static uintptr_t access8_if(uintptr_t addr) {
  return inited ? *(uint8_t*)MemToShadow(addr) : 0;
}
static uintptr_t access4_if(uintptr_t addr) {
  if (!inited) return 0;
  uint8_t shadow = *(uint8_t*)MemToShadow(addr);
  return shadow && ((addr & 7U) >= shadow + 3U);
}
static uintptr_t access2_if(uintptr_t addr) {
  if (!inited) return 0;
  uint8_t shadow = *(uint8_t*)MemToShadow(addr);
  return shadow && ((addr & 7U) >= shadow + 1U);
}
static uintptr_t access1_if(uintptr_t addr) {
  if (!inited) return 0;
  uint8_t shadow = *(uint8_t*)MemToShadow(addr);
  return shadow && ((addr & 7U) >= shadow);
}

typedef void (*AsanReportCallback)(ADDRINT);
#define ACCESS_THEN(type)                                             \
static AsanReportCallback __asan_report_ ## type;                     \
static void type ## _then(/*CONTEXT *ctx, THREADID tid, */            \
                          ADDRINT addr,                               \
                          string *info) {                             \
  fprintf(stderr, "** This bug is detected in a dynamically "         \
          "instrumented library:\n** %s\n", info->c_str());           \
  __asan_report_ ## type(addr);                                       \
}

#if 0
  PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT,           \
                              (AFUNPTR)__asan_report_ ## type,        \
                              PIN_PARG(ADDRINT), addr,                \
                              PIN_PARG_END());                        \

#endif

ACCESS_THEN(load16)
ACCESS_THEN(load8)
ACCESS_THEN(load4)
ACCESS_THEN(load2)
ACCESS_THEN(load1)
ACCESS_THEN(store16)
ACCESS_THEN(store8)
ACCESS_THEN(store4)
ACCESS_THEN(store2)
ACCESS_THEN(store1)

void CallbackForTRACE(TRACE trace, void *v) {
  RTN rtn = TRACE_Rtn(trace);
  if (!RTN_Valid(rtn)) return;
  string rtn_name = RTN_Name(rtn);
  string img_name = IMG_Name(SEC_Img(RTN_Sec(rtn)));

  // Don't instrument libc -- it is too asan-hostile.
  // Also, parts of libc (e.g. memcpy) are called on shadow memory inside asan.
  if (img_name.find("/libc") != string::npos) return;

  if (img_name.find("pintest_so.so") == string::npos &&
      img_name.find("/usr/lib/") != 0 &&
      img_name.find("/lib/") != 0)
    return;
  // printf("rtn: %s %s\n", rtn_name.c_str(), img_name.c_str());
  string *info = new string (rtn_name + " (" + img_name + ")");

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      int n_mops = INS_MemoryOperandCount(ins);
      for (int i = 0; i < n_mops; i++) {
        bool is_write = INS_MemoryOperandIsWritten(ins, i);
        size_t size = INS_MemoryOperandSize(ins, i);
        AFUNPTR callback1 = NULL, callback2 = NULL;
#define SWITCH_CALLBACK(s, w, cb_if, cb_then) \
        if (size == s && is_write == w) {     \
          callback1 = (AFUNPTR)cb_if;         \
          callback2 = (AFUNPTR)cb_then;       \
        }
        SWITCH_CALLBACK(16, true, access16_if, store16_then);
        SWITCH_CALLBACK(8,  true, access8_if,  store8_then);
        SWITCH_CALLBACK(4,  true, access4_if,  store4_then);
        SWITCH_CALLBACK(2,  true, access2_if,  store2_then);
        SWITCH_CALLBACK(1,  true, access1_if,  store1_then);
        SWITCH_CALLBACK(16, false, access16_if, load16_then);
        SWITCH_CALLBACK(8,  false, access8_if,  load8_then);
        SWITCH_CALLBACK(4,  false, access4_if,  load4_then);
        SWITCH_CALLBACK(2,  false, access2_if,  load2_then);
        SWITCH_CALLBACK(1,  false, access1_if,  load1_then);
#undef SWITCH_CALLBACK
        if (callback1 && callback2) {
          INS_InsertIfCall(ins, IPOINT_BEFORE, callback1,
                           IARG_MEMORYOP_EA, i, IARG_END);
          INS_InsertThenCall(ins, IPOINT_BEFORE, callback2,
                           // IARG_CONTEXT, IARG_THREAD_ID,
                           IARG_MEMORYOP_EA, i,
                           IARG_PTR, info,
                           IARG_END);
        }
      }
    }
  }
}

void CallbackForIMG(IMG img, void *v) {
  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
      string rtn_name = RTN_Name(rtn);
#define SWITCH_FUN(name) \
      if (rtn_name == #name) { name = (AsanReportCallback)RTN_Address(rtn); }
      SWITCH_FUN(__asan_report_store16);
      SWITCH_FUN(__asan_report_store8);
      SWITCH_FUN(__asan_report_store4);
      SWITCH_FUN(__asan_report_store2);
      SWITCH_FUN(__asan_report_store1);
      SWITCH_FUN(__asan_report_load16);
      SWITCH_FUN(__asan_report_load8);
      SWITCH_FUN(__asan_report_load4);
      SWITCH_FUN(__asan_report_load2);
      SWITCH_FUN(__asan_report_load1);
#undef SWITCH_FUN
      if (rtn_name == "__asan_init") {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_AFTER, AfterAsanInit, IARG_END);
        RTN_Close(rtn);
      }
    }
  }
}

int main(INT32 argc, CHAR **argv) {
  PIN_Init(argc, argv);
  PIN_InitSymbols();
  IMG_AddInstrumentFunction(CallbackForIMG, 0);
  TRACE_AddInstrumentFunction(CallbackForTRACE, 0);
  PIN_StartProgram();
  return 0;
}
