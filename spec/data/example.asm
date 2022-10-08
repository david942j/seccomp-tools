# An example of supported assembly syntax
if (A == X)
  goto next # 'next' is a reserved label, means the next statement ("A = args[0]" in this example)
else
  goto err_label # custom defined label
A = args[0]
if (
  A # put a comment here is also valid
    == 0x123
  ) goto disallow
if (! (A & 0x1337)) # support bang in if-conditions
  goto 0 # equivalent to 'goto next'
else goto 2 # goto $ + 2, 'mem[0] = A' in this example
A = sys_number
A = instruction_pointer >> 32
mem[0] = A
A = data[4] # equivalent to 'A = arch'
err_label: return ERRNO(1337)
disallow:
return KILL
