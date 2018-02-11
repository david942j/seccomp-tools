# check if arch is X86_64
A = arch
A == ARCH_X86_64 ? next : dead
A = sys_number
A >= 0x40000000 ? dead : next
A == write ? ok : next
A == close ? ok : next
A == dup ? ok : next
A == exit ? ok : next
return ERRNO(5)
ok:
return ALLOW
dead:
return KILL
