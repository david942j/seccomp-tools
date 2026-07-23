# A deliberately convoluted amd64 filter that exercises the symbolic engine:
# data-to-data arithmetic, immediate-rooted arithmetic, scratch memory,
# X-register comparisons, and several distinct verdicts. Assemble with
#   seccomp-tools asm spec/data/complex.asm -a amd64

A = arch
A == ARCH_X86_64 ? next : kill_it         # non-amd64 -> KILL

A = sys_number
A >= 0x40000000 ? kill_it : next          # x32 ABI -> KILL

A == write  ? check_write  : next
A == openat ? check_openat : next
A == read   ? allow        : next
return TRACE(1)                           # everything else is traced

check_write:
  # allow only if (count & fd) & 0xffff == buf | 0x10
  A = args[0]                             # fd
  X = A
  A = args[2]                             # count
  A &= X                                  # count & fd            (data & data)
  A &= 0xffff
  mem[0] = A                              # stash the left side
  A = args[1]                             # buf
  A |= 0x10                               # buf | 0x10            (right side)
  X = A
  A = mem[0]
  A == X ? allow : deny

check_openat:
  # errno unless (0x1337 & filename) == flags
  A = args[1]                             # filename
  X = A
  A = 0x1337
  A &= X                                  # 0x1337 & filename     (immediate-rooted)
  X = A
  A = args[2]                             # flags
  A == X ? allow : deny

allow:
  return ALLOW
deny:
  return ERRNO(1)
kill_it:
  return KILL
