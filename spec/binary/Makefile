all: clone_two_seccomp libseccomp syscall_seccomp

%: %.c
	cc $< -o $@ -lseccomp
