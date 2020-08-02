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
  switch(argc) {
    case 2:
        return strverscmp(s, "ABC xyz1");
    case 3:
        printf("getenv: %s\n", getenv(str));
        return 0;

    case 4:
        gethostbyname(str);
        return 0;

    case 5:
        fnmatch(str, "zzz", 0);
        return 0;
        
    case 6:
        printf("strstr: %s\n", strstr(str, "zzz"));
        return 0;

    case 7: {
        char *s1 = strdup("aaa");
        char *s2 = strdup("abc");
        printf("strcspn: %zd\n", strcspn(s1, s2));
        free(s1);
        free(s2);
        return 0;
    }

    default: {
        char *tok = strsep(&s, " ");
        printf("tok %p\n", tok);
        printf("tok: |%s|; s: |%s|\n", tok, s);
    }
  }
}
