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

#ifndef ASAN_STATS_H
#define ASAN_STATS_H
struct AsanStats {
  size_t low_shadow_maps;
  size_t high_shadow_maps;
  size_t mallocs;
  size_t malloced;
  size_t malloced_redzones;
  size_t frees;
  size_t freed;
  size_t real_frees;
  size_t really_freed;
  size_t reallocs;
  size_t realloced;
  size_t allocated_since_last_stats;
  size_t mmaps;
  size_t mmaped;
  size_t mmaped_by_size[__WORDSIZE];
  size_t malloced_by_size[__WORDSIZE];
  size_t freed_by_size[__WORDSIZE];
  size_t really_freed_by_size[__WORDSIZE];

  void PrintStats();
};

extern AsanStats __asan_stats;

#endif  // ASAN_STATS_H
