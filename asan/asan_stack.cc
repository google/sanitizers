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

#include "asan_stack.h"

#include "asan_thread.h"
#include "sysinfo.h"
//#include "bfd_symbolizer/bfd_symbolizer.h"

#include <string.h>
#include <string>

using std::string;
// ----------------------- ProcSelfMaps ----------------------------- {{{1
class ProcSelfMaps {
 public:
  void Init() {
    ProcMapsIterator it(0, &proc_self_maps_);   // 0 means "current pid"

    uint64 start, end, offset;
    int64 inode;
    char *flags, *filename;
    map_size_ = 0;
    while (it.Next(&start, &end, &flags, &offset, &inode, &filename)) {
      CHECK(map_size_ < kMaxProcSelfMapsSize);
      Mapping &mapping = memory_map[map_size_];
      mapping.beg = start;
      mapping.end = end;
      strncpy(mapping.name, filename, ASAN_ARRAY_SIZE(mapping.name));
      mapping.name[ASAN_ARRAY_SIZE(mapping.name) - 1] = 0;
      map_size_++;
      if (__asan_flag_v) {
        Printf(""PP"-"PP" %s\n", mapping.name);
      }
    }
  }

  void Print() {
    Printf("%s\n", proc_self_maps_);
  }

  void FilterOutAsanRtlFileName(char file_name[]) {
    if (strstr(file_name, "asan_rtl.cc")) {
      strcpy(file_name,   "_asan_rtl_");
    }
  }

  void PrintPc(uintptr_t pc, int idx) {
    const int kLen = 1024;
#if 0 // In-process symbolizer is disabled for now, too cranky
    char func[kLen+1] = "",
         file[kLen+1] = "",
         module[kLen+1] = "";
    int line = 0;
    int offset = 0;

    if (0 && __asan_flag_symbolize) {
      int opt = bfds_opt_none;
      if (idx == 0)
        opt |= bfds_opt_update_libs;
      int demangle = __asan_flag_demangle;
      if (demangle == 1) opt |= bfds_opt_demangle;
      if (demangle == 2) opt |= bfds_opt_demangle_params;
      if (demangle == 3) opt |= bfds_opt_demangle_verbose;
      int res = bfds_symbolize((void*)pc,
                               (bfds_opts_e)opt,
                               func, kLen,
                               module, kLen,
                               file, kLen,
                               &line,
                               &offset);
      if (res == 0) {
        FilterOutAsanRtlFileName(file);
        Printf("    #%d 0x%lx in %s %s:%d\n", idx, pc, func, file, line);
        return;
      }
      // bfd failed
    }
#endif

    for (size_t i = 0; i < map_size_; i++) {
      Mapping &m = memory_map[i];
      if (pc >= m.beg && pc < m.end) {
        uintptr_t offset = pc - m.beg;
        if (i == 0) offset = pc;
        Printf("    #%d 0x%lx (%s+0x%lx)\n", idx, pc, m.name, offset);
        return;
      }
    }
    Printf("  #%d 0x%lx\n", idx, pc);
  }

 private:
  void copy_until_new_line(const char *str, char *dest, size_t max_size) {
    size_t i = 0;
    for (; str[i] && str[i] != '\n' && i < max_size - 1; i++){
      dest[i] = str[i];
    }
    dest[i] = 0;
  }


  struct Mapping {
    uintptr_t beg, end;
    char name[1000];
  };
  static const size_t kMaxNumMapEntries = 4096;
  static const size_t kMaxProcSelfMapsSize = 1 << 20;
  ProcMapsIterator::Buffer proc_self_maps_;
  size_t map_size_;
  Mapping memory_map[kMaxNumMapEntries];
};

static ProcSelfMaps proc_self_maps;

// ----------------------- AsanStackTrace ----------------------------- {{{1

void AsanStackTrace::PrintStack(uintptr_t *addr, size_t size) {
  for (size_t i = 0; i < size && addr[i]; i++) {
    uintptr_t pc = addr[i];
    string img, rtn, file;
    // int line;
    // PcToStrings(pc, true, &img, &rtn, &file, &line);
    proc_self_maps.PrintPc(pc, i);
    // Printf("  #%ld 0x%lx %s\n", i, pc, rtn.c_str());
    if (rtn == "main()") break;
  }
}

void AsanStackTrace::Init() {
  proc_self_maps.Init();
}

_Unwind_Reason_Code AsanStackTrace::Unwind_Trace(
    struct _Unwind_Context *ctx, void *param) {
  AsanStackTrace *b = (AsanStackTrace*)param;
  CHECK(b->size < b->max_size);
  b->trace[b->size] = _Unwind_GetIP(ctx);
  // Printf("ctx: %p ip: %lx\n", ctx, b->buff[b->cur]);
  b->size++;
  if (b->size == b->max_size) return _URC_NORMAL_STOP;
  return _URC_NO_REASON;
}

void AsanStackTrace::FastUnwindStack(uintptr_t *frame) {
  size = 0;
  trace[size++] = GET_CALLER_PC();
  AsanThread *t = AsanThread::GetCurrent();
  if (!t) return;
  uintptr_t *prev_frame = frame;
  uintptr_t *top = (uintptr_t*)t->stack_top();
  while (frame >= prev_frame &&
         frame < top &&
         size < max_size) {
    uintptr_t pc = frame[1];
    trace[size++] = pc;
    prev_frame = frame;
    frame = (uintptr_t*)frame[0];
  }
}

void AsanStackTrace::PrintCurrent(uintptr_t pc) {
  GET_STACK_TRACE_HERE(kStackTraceMax, /*fast unwind*/false);
  CHECK(stack.size >= 2);
  size_t skip_frames = 1;
  if (pc) {
    // find this pc, should be somewehre around 3-rd frame
    for (size_t i = skip_frames; i < stack.size; i++) {
      if (stack.trace[i] == pc) {
        skip_frames = i;
        break;
      }
    }
  }
  PrintStack(stack.trace + skip_frames, stack.size - skip_frames);
}
