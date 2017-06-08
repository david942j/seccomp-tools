all: clone_two_seccomp libseccomp

%: %.c
	cc $< -o $@ -lseccomp
