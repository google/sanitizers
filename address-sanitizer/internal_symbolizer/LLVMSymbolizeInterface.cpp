#include "LLVMSymbolize.h"
#include <stdio.h>
#include <string>

/* C interface for LLVMSymbolize library */

static bool DemangleEnabled = true;

static llvm::symbolize::LLVMSymbolizer *getDefaultSymbolizer() {
  static llvm::symbolize::LLVMSymbolizer *DefaultSymbolizer = 0;
  if (DefaultSymbolizer == 0) {
    llvm::symbolize::LLVMSymbolizer::Options opts(true, true, true,
                                                  DemangleEnabled);
    DefaultSymbolizer = new llvm::symbolize::LLVMSymbolizer(opts);
  }
  return DefaultSymbolizer;
}

extern "C" {

// Must be called before the first call to __llvm_symbolize_*
__attribute__((visibility("default")))
void __llvm_symbolize_set_demangling(bool DoDemangle) {
  DemangleEnabled = DoDemangle;
}

__attribute__((visibility("default")))
bool __llvm_symbolize_code(const char *ModuleName, uint64_t ModuleOffset,
                           char *Buffer, int MaxLength) {
  std::string Result = getDefaultSymbolizer()->symbolizeCode(ModuleName,
                                                             ModuleOffset);
  snprintf(Buffer, MaxLength, "%s", Result.c_str());
  return true;
}

__attribute__((visibility("default")))
bool __llvm_symbolize_data(const char *ModuleName, uint64_t ModuleOffset,
                           char *Buffer, int MaxLength) {
  std::string Result = getDefaultSymbolizer()->symbolizeData(ModuleName,
                                                             ModuleOffset);
  snprintf(Buffer, MaxLength, "%s", Result.c_str());
  return true;
}

__attribute__((visibility("default")))
void __llvm_symbolize_flush() {
  getDefaultSymbolizer()->flush();
}

__attribute__((visibility("default")))
int __llvm_symbolize_demangle(const char *Name, char *Buffer, int MaxLength) {
  std::string Result =
      DemangleEnabled ? llvm::symbolize::LLVMSymbolizer::DemangleName(Name)
                      : Name;
  snprintf(Buffer, MaxLength, "%s", Result.c_str());
  return static_cast<int>(Result.size() + 1);
}

}  // extern "C"
