  .globl install_seccomp
install_seccomp:
  lghi   %r1, 172   /* __NR_prctl */
  lghi   %r2, 38    /* PR_SET_NO_NEW_PRIVS */
  lghi   %r3, 1
  xgr    %r4, %r4
  xgr    %r5, %r5
  xgr    %r6, %r6
  svc    0

  lghi   %r1, 172   /* __NR_prctl */
  lghi   %r2, 22    /* PR_SET_SECCOMP */
  lghi   %r3, 2     /* SECCOMP_MODE_FILTER */
  aghi   %r15, -16  /* sizeof(struct sock_fprog) */
  mvhhi  0(%r15), (_filter_end - _filter) >> 3  /* .len */
  larl   %r4, _filter
  stg    %r4, 8(%r15)                           /* .filter */
  lgr    %r4, %r15
  svc    0
  aghi   %r15, 16

  br     %r14

_filter:
.ascii "<TO_BE_REPLACED>"
_filter_end:
