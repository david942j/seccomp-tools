[![Build Status](https://github.com/david942j/seccomp-tools/workflows/build/badge.svg)](https://github.com/david942j/seccomp-tools/actions)
[![Code Climate](https://codeclimate.com/github/david942j/seccomp-tools/badges/gpa.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Issue Count](https://codeclimate.com/github/david942j/seccomp-tools/badges/issue_count.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Test Coverage](https://codeclimate.com/github/david942j/seccomp-tools/badges/coverage.svg)](https://codeclimate.com/github/david942j/seccomp-tools/coverage)
[![Inline docs](https://inch-ci.org/github/david942j/seccomp-tools.svg?branch=master)](https://inch-ci.org/github/david942j/seccomp-tools)
[![Yard Docs](http://img.shields.io/badge/yard-docs-blue.svg)](https://www.rubydoc.info/github/david942j/seccomp-tools/)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

# Seccomp Tools
Provide powerful tools for seccomp analysis.

This project targets to (but is not limited to) analyze seccomp sandbox in CTF pwn challenges.
Some features might be CTF-specific, but also useful for analyzing seccomp of real cases.

## Features
* Dump - Automatically dumps seccomp BPF from execution file(s).
* Disasm - Converts seccomp BPF to a human readable format.
  - With simple decompilation.
  - With syscall names and arguments whenever possible.
  - Colorful!
* Asm - Makes writing seccomp rules similar to writing codes.
* Emu - Emulates seccomp rules.
* Supports multi-architecture.

## Installation

Available on RubyGems.org!
```
$ gem install seccomp-tools
```

If you failed when compiling, try:
```
sudo apt install gcc ruby-dev
```
and install seccomp-tools again.

## Command Line Interface

### seccomp-tools

```bash
SHELL_OUTPUT_OF(seccomp-tools --help)
SHELL_OUTPUT_OF(seccomp-tools dump --help)
```

### dump

Dumps the seccomp BPF from an execution file.
This work is done by utilizing the `ptrace` syscall.

NOTICE: beware of the execution file will be executed.
```bash
SHELL_OUTPUT_OF(file spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f inspect)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f raw | xxd)
```

### disasm

Disassembles the seccomp from raw BPF.
```bash
SHELL_OUTPUT_OF(xxd spec/data/twctf-2016-diary.bpf | head -n 3)
SHELL_OUTPUT_OF(seccomp-tools disasm spec/data/twctf-2016-diary.bpf)
```

### asm

Assembles the seccomp rules into raw bytes.
It's very useful when one wants to write custom seccomp rules.

Supports labels for jumping and uses syscall names directly. See examples below.
```bash
SHELL_OUTPUT_OF(seccomp-tools asm)
# Input file for asm
SHELL_OUTPUT_OF(cat spec/data/libseccomp.asm)
SHELL_OUTPUT_OF(seccomp-tools asm spec/data/libseccomp.asm)
SHELL_OUTPUT_OF(seccomp-tools asm spec/data/libseccomp.asm -f c_source)
SHELL_OUTPUT_OF(seccomp-tools asm spec/data/libseccomp.asm -f assembly)

# let's asm then disasm!
SHELL_OUTPUT_OF(seccomp-tools asm spec/data/libseccomp.asm -f raw | seccomp-tools disasm -)
```

Since v1.6.0 [not released yet], `asm` has switched to using a yacc-based syntax parser, hence supports more flexible and intuitive syntax!

```bash
SHELL_OUTPUT_OF(cat spec/data/example.asm)
SHELL_OUTPUT_OF(seccomp-tools asm spec/data/example.asm -f raw | seccomp-tools disasm -)
```

The output of `seccomp-tools disasm <file> --asm-able` is a valid input of `asm`:
```bash
SHELL_OUTPUT_OF(seccomp-tools disasm spec/data/x32.bpf --asm-able)

# disasm then asm then disasm!
SHELL_OUTPUT_OF(seccomp-tools disasm spec/data/x32.bpf --asm-able | seccomp-tools asm - -f raw | seccomp-tools disasm -)
```

### Emu

Emulates seccomp given `sys_nr`, `arg0`, `arg1`, etc.
```bash
SHELL_OUTPUT_OF(seccomp-tools emu --help)
SHELL_OUTPUT_OF(seccomp-tools emu spec/data/libseccomp.bpf write 0x3)
```

## Screenshots

### Dump
![dump](https://github.com/david942j/seccomp-tools/blob/master/examples/dump-diary.png?raw=true)

### Emu
![emu](https://github.com/david942j/seccomp-tools/blob/master/examples/emu-libseccomp.png?raw=true)

![emu](https://github.com/david942j/seccomp-tools/blob/master/examples/emu-amigo.png?raw=true)

## Supported Architectures

- [x] x86_64
- [x] x32
- [x] x86
- [x] arm64 (@saagarjha)
- [x] s390x (@iii-i)

Pull Requests of adding more architectures support are welcome!

## Development

I recommend to use [rbenv](https://github.com/rbenv/rbenv) for your Ruby environment.

### Setup

- Install bundler
  - `$ gem install bundler`
- Clone the source
  - `$ git clone https://github.com/david942j/seccomp-tools && cd seccomp-tools`
- Install dependencies
  - `$ bundle install`

### Run tests

`$ bundle exec rake`

## I Need You

Any suggestions or feature requests are welcome!
Feel free to file issues or send pull requests.
And, if you like this work, I'll be happy to be [starred](https://github.com/david942j/seccomp-tools/stargazers) :grimacing:
