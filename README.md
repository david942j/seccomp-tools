[![Build Status](https://travis-ci.org/david942j/seccomp-tools.svg?branch=master)](https://travis-ci.org/david942j/seccomp-tools)
[![Code Climate](https://codeclimate.com/github/david942j/seccomp-tools/badges/gpa.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Issue Count](https://codeclimate.com/github/david942j/seccomp-tools/badges/issue_count.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Test Coverage](https://codeclimate.com/github/david942j/seccomp-tools/badges/coverage.svg)](https://codeclimate.com/github/david942j/seccomp-tools/coverage)
[![Inline docs](https://inch-ci.org/github/david942j/seccomp-tools.svg?branch=master)](https://inch-ci.org/github/david942j/seccomp-tools)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

# Seccomp Tools
Provides powerful tools for seccomp analysis.

This project is targeted to (but not limited to) analyze seccomp sandbox in CTF pwn challenges.
Some features might be CTF-specific, but still useful for analysis of seccomp in real-case.

## Features
* Dump - Automatically dump seccomp-bpf from binary.
* Disasm - Convert bpf to human readable format.
  - Simple decompile.
  - Show syscall names.
* Asm - Write seccomp rules is so easy!
* Emu - Emulate seccomp rules.
* (TODO) Solve constraints for executing syscalls (e.g. `execve/open/read/write`).
* Support multi-architectures.

## Installation

Available on RubyGems.org!
```
$ gem install seccomp-tools
```

## Command Line Interface

### seccomp-tools

```bash
$ seccomp-tools --help
# Usage: seccomp-tools [--version] [--help] <command> [<options>]
#
# List of commands:
#
# 	dump	Automatically dump seccomp bpf from execution file.
# 	disasm	Disassemble seccomp bpf.
# 	asm	Seccomp bpf assembler.
# 	emu	Emulate seccomp rules.
#
# See 'seccomp-tools --help <command>' to read about a specific subcommand.

$ seccomp-tools --help dump
# dump - Automatically dump seccomp bpf from execution file.
#
# Usage: seccomp-tools dump [exec] [options]
#     -c, --sh-exec <command>          Executes the given command (via sh).
#                                      Use this option if want to pass arguments or do pipe things to the execution file.
#     -f, --format FORMAT              Output format. FORMAT can only be one of <disasm|raw|inspect>.
#                                      Default: disasm
#     -l, --limit LIMIT                Limit the number of calling "prctl(PR_SET_SECCOMP)".
#                                      The target process will be killed whenever its calling times reaches LIMIT.
#                                      Default: 1
#     -o, --output FILE                Output result into FILE instead of stdout.
#                                      If multiple seccomp syscalls have been invoked (see --limit),
#                                      results will be written to FILE, FILE_1, FILE_2.. etc.
#                                      For example, "--output out.bpf" and the output files are out.bpf, out_1.bpf, ...

```

### dump

Dump the seccomp bpf from an execution file.
This work is done by the `ptrace` syscall.

NOTICE: beware of the execution file will be executed.
```bash
$ file spec/binary/twctf-2016-diary
# spec/binary/twctf-2016-diary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=3648e29153ac0259a0b7c3e25537a5334f50107f, not stripped

$ seccomp-tools dump spec/binary/twctf-2016-diary
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0001: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0003
#  0002: 0x06 0x00 0x00 0x00000000  return KILL
#  0003: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0005
#  0004: 0x06 0x00 0x00 0x00000000  return KILL
#  0005: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0007
#  0006: 0x06 0x00 0x00 0x00000000  return KILL
#  0007: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0009
#  0008: 0x06 0x00 0x00 0x00000000  return KILL
#  0009: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0011
#  0010: 0x06 0x00 0x00 0x00000000  return KILL
#  0011: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0013
#  0012: 0x06 0x00 0x00 0x00000000  return KILL
#  0013: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0015
#  0014: 0x06 0x00 0x00 0x00000000  return KILL
#  0015: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0017
#  0016: 0x06 0x00 0x00 0x00000000  return KILL
#  0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW

$ seccomp-tools dump spec/binary/twctf-2016-diary -f inspect
# "\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3B\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x38\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x39\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3A\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x55\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x42\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"

$ seccomp-tools dump spec/binary/twctf-2016-diary -f raw | xxd
# 00000000: 2000 0000 0000 0000 1500 0001 0200 0000   ...............
# 00000010: 0600 0000 0000 0000 1500 0001 0101 0000  ................
# 00000020: 0600 0000 0000 0000 1500 0001 3b00 0000  ............;...
# 00000030: 0600 0000 0000 0000 1500 0001 3800 0000  ............8...
# 00000040: 0600 0000 0000 0000 1500 0001 3900 0000  ............9...
# 00000050: 0600 0000 0000 0000 1500 0001 3a00 0000  ............:...
# 00000060: 0600 0000 0000 0000 1500 0001 5500 0000  ............U...
# 00000070: 0600 0000 0000 0000 1500 0001 4201 0000  ............B...
# 00000080: 0600 0000 0000 0000 0600 0000 0000 ff7f  ................

```

### disasm

Disassemble the seccomp from raw bpf.
```bash
$ xxd spec/data/twctf-2016-diary.bpf | head -n 3
# 00000000: 2000 0000 0000 0000 1500 0001 0200 0000   ...............
# 00000010: 0600 0000 0000 0000 1500 0001 0101 0000  ................
# 00000020: 0600 0000 0000 0000 1500 0001 3b00 0000  ............;...

$ seccomp-tools disasm spec/data/twctf-2016-diary.bpf
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0001: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0003
#  0002: 0x06 0x00 0x00 0x00000000  return KILL
#  0003: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0005
#  0004: 0x06 0x00 0x00 0x00000000  return KILL
#  0005: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0007
#  0006: 0x06 0x00 0x00 0x00000000  return KILL
#  0007: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0009
#  0008: 0x06 0x00 0x00 0x00000000  return KILL
#  0009: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0011
#  0010: 0x06 0x00 0x00 0x00000000  return KILL
#  0011: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0013
#  0012: 0x06 0x00 0x00 0x00000000  return KILL
#  0013: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0015
#  0014: 0x06 0x00 0x00 0x00000000  return KILL
#  0015: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0017
#  0016: 0x06 0x00 0x00 0x00000000  return KILL
#  0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```

### asm

Assemble the seccomp rules into raw bytes.
Very useful when want to write custom seccomp rules.

Supports labels for jumping and use syscall names directly. See example below.
```bash
$ seccomp-tools asm
# asm - Seccomp bpf assembler.
#
# Usage: seccomp-tools asm IN_FILE [options]
#     -o, --output FILE                Output result into FILE instead of stdout.
#     -f, --format FORMAT              Output format. FORMAT can only be one of <inspect|raw|carray>.
#                                      Default: inspect
#     -a, --arch ARCH                  Specify architecture.
#                                      Supported architectures are <amd64|i386>.

# Input file for asm
$ cat spec/data/libseccomp.asm
# # check if arch is X86_64
# A = arch
# A == 0xc000003e ? next : dead
# A = sys_number
# A >= 0x40000000 ? dead : next
# A == write ? ok : next
# A == close ? ok : next
# A == dup ? ok : next
# A == exit ? ok : next
# return ERRNO(5)
# ok:
# return ALLOW
# dead:
# return KILL

$ seccomp-tools asm spec/data/libseccomp.asm
# " \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\b>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x005\x00\x06\x00\x00\x00\x00@\x15\x00\x04\x00\x01\x00\x00\x00\x15\x00\x03\x00\x03\x00\x00\x00\x15\x00\x02\x00 \x00\x00\x00\x15\x00\x01\x00<\x00\x00\x00\x06\x00\x00\x00\x05\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00"

$ seccomp-tools asm spec/data/libseccomp.asm -f carray
# unsigned char bpf[] = {32,0,0,0,4,0,0,0,21,0,0,8,62,0,0,192,32,0,0,0,0,0,0,0,53,0,6,0,0,0,0,64,21,0,4,0,1,0,0,0,21,0,3,0,3,0,0,0,21,0,2,0,32,0,0,0,21,0,1,0,60,0,0,0,6,0,0,0,5,0,5,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};


# let's asm then disasm!
$ seccomp-tools asm spec/data/libseccomp.asm -f raw | seccomp-tools disasm -
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
#  0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
#  0005: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0009
#  0006: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0009
#  0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
#  0008: 0x06 0x00 0x00 0x00050005  return ERRNO
#  0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0010: 0x06 0x00 0x00 0x00000000  return KILL

```

### Emu

Emulate seccomp given `sys_nr`, `arg0`, `arg1`, etc.
```bash
$ seccomp-tools emu --help
# emu - Emulate seccomp rules.
#
# Usage: seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 [arg1 ... arg5]]]
#     -a, --arch ARCH                  Specify architecture.
#                                      Supported architectures are <amd64|i386>.
#     -q, --[no-]quiet                 Run quietly, only show emulation result.

$ seccomp-tools emu spec/data/libseccomp.bpf 0x3
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
#  0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
#  0005: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0009
#  0006: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0009
#  0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
#  0008: 0x06 0x00 0x00 0x00050005  return ERRNO
#  0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0010: 0x06 0x00 0x00 0x00000000  return KILL
#
# return ALLOW at line 0009

```

## Screenshots

### Dump
![dump](https://github.com/david942j/seccomp-tools/blob/master/examples/dump-diary.png?raw=true)

### Emu
![emu](https://github.com/david942j/seccomp-tools/blob/master/examples/emu-libseccomp.png?raw=true)

![emu](https://github.com/david942j/seccomp-tools/blob/master/examples/emu-amigo.png?raw=true)

## I Need You
Any suggestion or feature request is welcome!
Feel free to file an issue or send a pull request.
And, if you like this work, I'll be happy to be [stared](https://github.com/david942j/seccomp-tools/stargazers) :grimacing:
