#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct A{
  size_t len;
  unsigned char* s;
} a;
int main() {
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  pid_t pid = fork();
  if(pid == 0) {
    unsigned char z[] = {0x20, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0xff, 0x7f};
    a.len = 2;
    a.s = z;
    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &a)) perror("prctl");
  }
  else {
    unsigned char z[] = {6, 0, 0, 0, 0, 0, 0xff, 0x7f};
    a.len = 1;
    a.s = z;
    int status;
    waitpid(pid, &status, 0);
    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &a)) perror("prctl");
    // let's install an invalid seccomp
    memset(z, 0, sizeof(z));
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &a);
  }
  return 0;
}
