A = arch
if (A != ARCH_X86_64) goto i386
A = sys_number
if (A >= 0x40000000) goto dead
if (A == 0) goto allow
if (A == 1) goto allow
if (A == 2) goto allow else goto dead

i386: if (A != ARCH_I386) goto arm64
A = sys_number
if (A == 0) goto allow
if (A == 1) goto allow
if (A == 2) goto allow else goto dead

arm64: if (A != ARCH_AARCH64) goto s390x
A = sys_number
if (A == 0) goto allow
if (A == 1) goto allow
if (A == 2) goto allow else goto dead

s390x: if (A != ARCH_S390X) goto dead
A = sys_number
if (A == 0) goto allow
if (A == 1) goto allow
if (A == 2) goto allow else goto dead

dead: return KILL
allow: return ALLOW
