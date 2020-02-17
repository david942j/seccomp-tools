/*
 * Installs two seccomp filters and waits for stdin.
 */

#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/prctl.h>

struct A {
  size_t len;
  unsigned char *s;
} a;

int main() {
  setbuf(stdout, NULL);
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  unsigned char f1[] = {0x20, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0xff, 0x7f};
  a.len = 2;
  a.s = f1;
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &a))
    perror("prctl");
  unsigned char f2[] = {6, 0, 0, 0, 0, 0, 0xff, 0x7f};
  a.len = 1;
  a.s = f2;
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &a))
    perror("prctl");
  puts("Done");
  scanf("%*c");

  return 0;
}
