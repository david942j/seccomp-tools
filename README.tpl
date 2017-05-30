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
SHELL_OUTPUT_OF(seccomp-tools)
SHELL_OUTPUT_OF(seccomp-tools help dump)
```

### dump

Dump the seccomp bpf from a execution file.
This work is done by the `ptrace` syscall.

NOTICE: beware of the execution file will be executed.
```bash
SHELL_OUTPUT_OF(file spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f inspect)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f raw | xxd)
```

### disasm

Disassemble the seccomp bpf.
```bash
SHELL_OUTPUT_OF(seccomp-tools disasm spec/data/twctf-2016-diary.bpf)
```