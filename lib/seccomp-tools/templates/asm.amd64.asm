install_seccomp:
  push   rbp
  mov    rbp, rsp
  push   38
  pop    rdi
  push   0x1
  pop    rsi
  xor    eax, eax
  mov    al, 0x9d
  syscall
  push   22
  pop    rdi
  lea    rdx, [rip + _filter]
  push   rdx /* .filter */
  push   _filter_end - _filter >> 3 /* .len */
  mov    rdx, rsp
  push   0x2
  pop    rsi
  xor    eax, eax
  mov    al, 0x9d
  syscall
  leave
  ret
_filter:
.ascii "<TO_BE_REPLACED>"
_filter_end:
