[![Build Status](https://travis-ci.org/david942j/seccomp-tools.svg?branch=master)](https://travis-ci.org/david942j/seccomp-tools)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=david942j/seccomp-tools)](https://dependabot.com)
[![Code Climate](https://codeclimate.com/github/david942j/seccomp-tools/badges/gpa.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Issue Count](https://codeclimate.com/github/david942j/seccomp-tools/badges/issue_count.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Test Coverage](https://codeclimate.com/github/david942j/seccomp-tools/badges/coverage.svg)](https://codeclimate.com/github/david942j/seccomp-tools/coverage)
[![Inline docs](https://inch-ci.org/github/david942j/seccomp-tools.svg?branch=master)](https://inch-ci.org/github/david942j/seccomp-tools)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

# Seccomp Tools
Provide powerful tools for seccomp analysis.

This project is targeted to (but not limited to) analyze seccomp sandbox in CTF pwn challenges.
Some features might be CTF-specific, but still useful for analyzing seccomp in real-case.

## Features
* Dump - Automatically dumps seccomp-bpf from execution file(s).
* Disasm - Converts bpf to human readable format.
  - Simple decompile.
  - Display syscall names and arguments when possible.
  - Colorful!
* Asm - Write seccomp rules is so easy!
* Emu - Emulates seccomp rules.
* Supports multi-architectures.

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

Dumps the seccomp bpf from an execution file.
This work is done by the `ptrace` syscall.

NOTICE: beware of the execution file will be executed.
```bash
SHELL_OUTPUT_OF(file spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f inspect)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f raw | xxd)
```

### disasm

Disassembles the seccomp from raw bpf.
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

Any suggestion or feature request is welcome!
Feel free to file an issue or send a pull request.
And, if you like this work, I'll be happy to be [starred](https://github.com/david942j/seccomp-tools/stargazers) :grimacing:
