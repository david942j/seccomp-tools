# Exercises operator-precedence rendering in `explain`. Each branch combines
# bitwise, shift and arithmetic operations so the summarized condition must be
# parenthesized exactly where C precedence would otherwise change its meaning
# (e.g. `==` binds tighter than `&`, and `<<` looser than `+`), and where two
# different bitwise operators mix (`a ^ b | c`) even though C would not require it.
# Assemble with: seccomp-tools asm spec/data/operator_precedence.asm -a amd64

A = arch
A == ARCH_X86_64 ? next : deny

A = sys_number
A == read   ? nested_bitwise : next
A == write  ? shift_vs_add   : next
A == openat ? relational     : next
A == close  ? bit_test       : next
A == lseek  ? mixed_bitwise  : next
A == poll   ? bitwise_chain  : next
A == fstat  ? arith_in_bitwise : next
A == dup2   ? arith_in_shift   : next
A == getpid ? mul_in_add       : next
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

mixed_bitwise:
  # ((fd ^ 0xff) | 0x1) == count     -- ^ binds tighter than |, but that is easy to
  #                                     misread, so the inner ^ is parenthesized
  A = args[0]        # fd
  A ^= 0xff
  A |= 0x1
  X = A
  A = args[2]        # count
  A == X ? allow : errno_it

bitwise_chain:
  # (fd ^ 0xff ^ 0x1) == count       -- a same-operator chain needs no inner parens
  A = args[0]        # fd
  A ^= 0xff
  A ^= 0x1
  X = A
  A = args[2]        # count
  A == X ? allow : errno_it

arith_in_bitwise:
  # (arg0 & (arg2 + 0x1)) == 0x5     -- arithmetic inside bitwise: different families, wrap
  A = args[2]
  A += 0x1
  X = A
  A = args[0]
  A &= X
  A == 0x5 ? allow : errno_it

arith_in_shift:
  # ((arg0 + arg1) << 0x2) == 0x100  -- arithmetic inside shift: different families, wrap
  A = args[1]
  X = A
  A = args[0]
  A += X
  A <<= 0x2
  A == 0x100 ? allow : errno_it

mul_in_add:
  # (arg0 + arg1 * 0x8) == 0x40      -- multiply inside add: universally understood, no wrap
  A = args[1]
  A *= 0x8
  X = A
  A = args[0]
  A += X
  A == 0x40 ? allow : errno_it

allow:
  return ALLOW
errno_it:
  return ERRNO(1)
deny:
  return KILL
