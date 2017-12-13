#include <stdio.h>
#include <string.h>

union Example {
  int i;
  float f;
  char s[20];
} ;

int main() {

  union Example e;

  printf("Hello %d", sizeof(e));

  return 0;
}