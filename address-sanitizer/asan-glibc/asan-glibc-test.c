#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wctype.h>
#include <netdb.h>
#include <fnmatch.h>

int main(int argc, char **argv) {
  char *str = strdup("ABC xyz10");
  char *s = str;
  free(str);
  if (argc == 2)
    return strverscmp(s, "ABC xyz1");
  if (argc == 3) {
    printf("getenv: %s\n", getenv(str));
    return 0;
  }
  if (argc == 4) {
    gethostbyname(str);
    return 0;
  }
  if (argc == 5) {
    fnmatch(str, "zzz", 0);
    return 0;
  }
  if (argc == 6) {
    printf("strstr: %s\n", strstr(str, "zzz"));
    return 0;
  }
  char *tok = strsep(&s, " ");
  printf("tok %p\n", tok);
  printf("tok: |%s|; s: |%s|\n", tok, s);
}
