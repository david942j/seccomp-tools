all: clone_two_seccomp libseccomp syscall_seccomp strict_prctl strict_seccomp

%: %.c
	cc $< -o $@ -lseccomp

strict_prctl strict_seccomp: gen_strict_mode.rb
	ruby $<
