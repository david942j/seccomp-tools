#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/prctl.h>

struct A{
  size_t len;
  unsigned char* s;
};
int main() {
  pid_t pid = fork();
  struct A a;
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  if(pid == 0) {
    unsigned char z[] = {0x20, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0xff, 0x7f};
    a.len = 2;
    a.s = z;
    if(prctl(22,2,&a)) perror("prctl");
  }
  else {
    unsigned char z[] = {6, 0, 0, 0, 0, 0, 0xff, 0x7f};
    a.len = 1;
    a.s = z;
    int status;
    waitpid(pid, &status, 0);
    if(prctl(22,2,&a)) perror("prctl");
  }
  return 0;
}
