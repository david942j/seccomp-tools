[![Build Status](https://travis-ci.org/david942j/seccomp-tools.svg?branch=master)](https://travis-ci.org/david942j/seccomp-tools)
[![Code Climate](https://codeclimate.com/github/david942j/seccomp-tools/badges/gpa.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Issue Count](https://codeclimate.com/github/david942j/seccomp-tools/badges/issue_count.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Test Coverage](https://codeclimate.com/github/david942j/seccomp-tools/badges/coverage.svg)](https://codeclimate.com/github/david942j/seccomp-tools/coverage)
[![Inline docs](https://inch-ci.org/github/david942j/seccomp-tools.svg?branch=master)](https://inch-ci.org/github/david942j/seccomp-tools)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

# seccomp-tools
Provides powerful tools for seccomp analysis.

## Features
* Dump - Automatically dump seccomp-bpf from binary.
* Disasm - (WIP) Convert bpf to human readable format.
  - Simple decompile.
  - (TODO) Show syscall names.
* (TODO) Solve constraints for executing syscalls (e.g. `execve/open/read/write`).
* (TODO) Support multi-architecture.

## Installation

(TODO)

## Command Line Interface

### seccomp-tools

All commands start from `seccomp-tools`.
```bash
$ seccomp-tools
Usage: seccomp-tools [--version] [--help] <command> [<options>]

These are list of commands:
	dump	Automatically dump seccomp bpf from execution file.
	disasm	Disassembly seccomp bpf.

See 'seccomp-tools help <command>' or 'seccomp-tools <command> -h' to read about a specific subcommand.

$ seccomp-tools help dump
dump - Automatically dump seccomp bpf from execution file.

Usage: seccomp-tools dump [exec] [options]
    -e, --exec <command>             Executes the given command.
                                     Use this option if want to pass arguments to the execution file.
    -f, --format FORMAT              Output format. FORMAT can only be one of <disasm|raw|inspect>.
                                     Default: disasm
    -l, --limit LIMIT                Limit the number of calling "prctl(PR_SET_SECCOMP)".
                                     The target process will be killed whenever its calling times reaches LIMIT.
                                     Default: 1
    -o, --output FILE                Output result into FILE instead of stdout.
                                     If multiple seccomp syscalls have been invoked (see --limit),
                                     results will be written to FILE, FILE_1, FILE_2.. etc.
                                     For example, "--output out.bpf" and the output files are out.bpf, out_1.bpf, ...

```

### dump

Dump the seccomp bpf from a execution file.
This work is done by the `ptrace` syscall.

NOTICE: beware of the execution file will be executed.
```bash
$ file spec/binary/twctf-2016-diary
spec/binary/twctf-2016-diary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=3648e29153ac0259a0b7c3e25537a5334f50107f, not stripped

$ seccomp-tools dump spec/binary/twctf-2016-diary
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x00000002  if (A != 2) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x00 0x01 0x00000101  if (A != 257) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x15 0x00 0x01 0x0000003b  if (A != 59) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x15 0x00 0x01 0x00000038  if (A != 56) goto 0009
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 0009: 0x15 0x00 0x01 0x00000039  if (A != 57) goto 0011
 0010: 0x06 0x00 0x00 0x00000000  return KILL
 0011: 0x15 0x00 0x01 0x0000003a  if (A != 58) goto 0013
 0012: 0x06 0x00 0x00 0x00000000  return KILL
 0013: 0x15 0x00 0x01 0x00000055  if (A != 85) goto 0015
 0014: 0x06 0x00 0x00 0x00000000  return KILL
 0015: 0x15 0x00 0x01 0x00000142  if (A != 322) goto 0017
 0016: 0x06 0x00 0x00 0x00000000  return KILL
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW

$ seccomp-tools dump spec/binary/twctf-2016-diary -f inspect
"\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3B\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x38\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x39\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3A\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x55\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x42\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"

$ seccomp-tools dump spec/binary/twctf-2016-diary -f raw | xxd
00000000: 2000 0000 0000 0000 1500 0001 0200 0000   ...............
00000010: 0600 0000 0000 0000 1500 0001 0101 0000  ................
00000020: 0600 0000 0000 0000 1500 0001 3b00 0000  ............;...
00000030: 0600 0000 0000 0000 1500 0001 3800 0000  ............8...
00000040: 0600 0000 0000 0000 1500 0001 3900 0000  ............9...
00000050: 0600 0000 0000 0000 1500 0001 3a00 0000  ............:...
00000060: 0600 0000 0000 0000 1500 0001 5500 0000  ............U...
00000070: 0600 0000 0000 0000 1500 0001 4201 0000  ............B...
00000080: 0600 0000 0000 0000 0600 0000 0000 ff7f  ................

```

### disasm

Disassemble the seccomp bpf.
```bash
$ seccomp-tools disasm spec/data/twctf-2016-diary.bpf
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x00000002  if (A != 2) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x00 0x01 0x00000101  if (A != 257) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x15 0x00 0x01 0x0000003b  if (A != 59) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x15 0x00 0x01 0x00000038  if (A != 56) goto 0009
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 0009: 0x15 0x00 0x01 0x00000039  if (A != 57) goto 0011
 0010: 0x06 0x00 0x00 0x00000000  return KILL
 0011: 0x15 0x00 0x01 0x0000003a  if (A != 58) goto 0013
 0012: 0x06 0x00 0x00 0x00000000  return KILL
 0013: 0x15 0x00 0x01 0x00000055  if (A != 85) goto 0015
 0014: 0x06 0x00 0x00 0x00000000  return KILL
 0015: 0x15 0x00 0x01 0x00000142  if (A != 322) goto 0017
 0016: 0x06 0x00 0x00 0x00000000  return KILL
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```
