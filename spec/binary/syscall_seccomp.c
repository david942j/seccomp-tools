#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

struct A{
  size_t len;
  unsigned char* s;
} a;
int main() {
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  unsigned char z[] = {6, 0, 0, 0, 0, 0, 0xff, 0x7f};
  a.len = 1;
  a.s = z;
  if(syscall(317, SECCOMP_SET_MODE_FILTER, 0, &a)) perror("seccomp");
  return 0;
}
