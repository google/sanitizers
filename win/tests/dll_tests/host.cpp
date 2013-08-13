/* Copyright 2013 Google Inc.
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

#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s [client].dll\n", argv[0]);
    return 1;
  }

  const char *dll_name = argv[1];

  HMODULE h = LoadLibrary(dll_name);
  if (!h) {
    printf("Could not load DLL: %s (code: %lu)!\n",
           dll_name, GetLastError());
    return 2;
  }

  typedef int (*test_function)();
  test_function gf = (test_function)GetProcAddress(h, "test_function");
  if (!gf) {
    printf("Could not locate test_function in the DLL!\n");
    FreeLibrary(h);
    return 13;
  }

  int ret = gf();

  FreeLibrary(h);
  return ret;
}
