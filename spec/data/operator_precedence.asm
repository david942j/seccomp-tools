# Exercises operator-precedence rendering in `explain`. Each branch combines
# bitwise, shift and arithmetic operations so the summarized condition must be
# parenthesized exactly where C precedence would otherwise change its meaning
# (e.g. `==` binds tighter than `&`, and `<<` looser than `+`).
# Assemble with: seccomp-tools asm spec/data/operator_precedence.asm -a amd64

A = arch
A == ARCH_X86_64 ? next : deny

A = sys_number
A == read   ? nested_bitwise : next
A == write  ? shift_vs_add   : next
A == openat ? relational     : next
A == close  ? bit_test       : next
return KILL

nested_bitwise:
  # ((fd | 0x1) & 0xff) == count      -- nested bitwise, both levels need parens
  A = args[0]        # fd
  A |= 0x1
  A &= 0xff
  X = A
  A = args[2]        # count
  A == X ? allow : errno_it

shift_vs_add:
  # count >> 4 == (buf << 2) + 0x8    -- << looser than +, so only << is wrapped
  A = args[1]        # buf
  A <<= 2
  A += 0x8
  X = A
  A = args[2]        # count
  A >>= 4
  A == X ? allow : errno_it

relational:
  # (flags & 0xf) < 0x5              -- < binds tighter than &
  A = args[2]        # flags
  A &= 0xf
  A < 0x5 ? allow : errno_it

bit_test:
  # (fd & 0x101) != 0                -- a jset bit test
  A = args[0]        # fd
  if (A & 0x101) goto allow else goto errno_it

allow:
  return ALLOW
errno_it:
  return ERRNO(1)
deny:
  return KILL
