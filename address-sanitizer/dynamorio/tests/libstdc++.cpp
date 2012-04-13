// Build with clang++ -faddress-sanitizer

#include <iostream>
using namespace std;

int main() {
  // Calls std::ios_base::Init::Init() which has
  // f0 41 0f c1 07  lock xadd %eax,(%r15)
  cout << "Hello!\n";// << endl;

  wchar_t wstr[] = {0};
  // Triggers a bug if the instrumentation messes up the aflags:
  // 48 85 c0             test   %rax %rax 
  //       <inserts instrumentation for the (%rbx) write here>
  // 48 89 03             mov    %rax -> (%rbx) 
  // 74 02                jz     <...>
  wcscasecmp(wstr, wstr);

  // 'endl' executes:
  // f3 a6    rep cmps %ds:(%rsi) %es:(%rdi) %rsi %rdi %rcx -> %rsi %rdi %rcx
  cout << "PASS" << endl;
}
