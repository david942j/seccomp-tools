/* Some syscalls in syscalls.h only have prototypes but no argument names, we add them here. */
asmlinkage long sys_io_submit(aio_context_t ctx_id, long nr, struct iocb __user * __user *iocbpp);
asmlinkage long sys_pselect6(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp,
                             struct __kernel_timespec __user *tsp, void __user *sig);
asmlinkage long sys_pselect6_time32(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp,
                                    struct old_timespec32 __user *tsp, void __user *sig);
asmlinkage long sys_ppoll(struct pollfd __user *ufds, unsigned int nfds, struct __kernel_timespec __user *tsp,
                          const sigset_t __user *sigmask, size_t sigsetsize);
asmlinkage long sys_ppoll_time32(struct pollfd __user *ufds, unsigned int nfds, struct old_timespec32 __user *tsp,
                                 const sigset_t __user *sigmask, size_t sigsetsize);
asmlinkage long sys_rt_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact,
                                 size_t sigsetsize);
asmlinkage long sys_socket(int family, int type, int protocol);
asmlinkage long sys_socketpair(int family, int type, int protocol, int __user *usockvec);
asmlinkage long sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen);
asmlinkage long sys_listen(int fd, int backlog);
asmlinkage long sys_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen);
asmlinkage long sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen);
asmlinkage long sys_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
asmlinkage long sys_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
asmlinkage long sys_sendto(int fd, void __user *buff, size_t len, unsigned flags, struct sockaddr __user *addr,
                           int addrlen);
asmlinkage long sys_recvfrom(int fd, void __user *ubuf, size_t len, unsigned flags, struct sockaddr __user *addr,
                             int __user *addrlen);
asmlinkage long sys_shutdown(int fd, int how);
asmlinkage long sys_clone(unsigned long clone_flags, unsigned long newsp, int __user *parent_tidptr,
                          int __user *child_tidptr, unsigned long tls);
asmlinkage long sys_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags);
asmlinkage long sys_recv(int fd, void __user *ubuf, size_t len, unsigned flags);
asmlinkage long sys_send(int fd, void __user *buff, size_t len, unsigned flags);
asmlinkage long sys_sigaction(int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact);
asmlinkage long sys_old_readdir(unsigned int fd, struct old_linux_dirent __user *dirent, unsigned int count);
asmlinkage long sys_uname(struct old_utsname __user *name);
asmlinkage long sys_olduname(struct oldold_utsname __user *name);

/* Syscalls not appear in syscalls.h. */
asmlinkage long sys_arch_prctl(int code, unsigned long addr);
asmlinkage long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags,
  unsigned long fd, unsigned long pgoff);

/* to have i386 compatiable */
asmlinkage long sys__llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result,
  unsigned int whence);
asmlinkage long sys__sysctl(struct __sysctl_args __user *args);
asmlinkage long sys__newselect(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp,
  struct timeval __user *tvp);
