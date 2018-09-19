install_seccomp:
  push   ebx
  push   ebp
  mov    ebp, esp
  push   38
  pop    ebx
  push   0x1
  pop    ecx
  xor    eax, eax
  mov    al, 0xac
  int    0x80
  push   22
  pop    ebx
  jmp    __get_eip__
__back__:
  pop    edx
  push   edx /* .filter */
  mov    edx, _filter_end - _filter >> 3 /* .len */
  push   edx
  mov    edx, esp
  push   0x2
  pop    ecx
  xor    eax, eax
  mov    al, 0xac
  int    0x80
  leave
  pop    ebx
  ret
__get_eip__:
  call __back__
_filter:
.ascii "<TO_BE_REPLACED>"
_filter_end:
