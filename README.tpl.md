[![Downloads](https://img.shields.io/gem/dt/seccomp-tools)](https://rubygems.org/gems/seccomp-tools)


[![Gem Version](https://badge.fury.io/rb/seccomp-tools.svg)](https://badge.fury.io/rb/seccomp-tools)
[![Build Status](https://github.com/david942j/seccomp-tools/workflows/build/badge.svg)](https://github.com/david942j/seccomp-tools/actions)
[![Maintainability](https://qlty.sh/gh/david942j/projects/seccomp-tools/maintainability.svg)](https://qlty.sh/gh/david942j/projects/seccomp-tools)
[![Code Coverage](https://qlty.sh/gh/david942j/projects/seccomp-tools/coverage.svg)](https://qlty.sh/gh/david942j/projects/seccomp-tools)
[![Inline docs](https://inch-ci.org/github/david942j/seccomp-tools.svg?branch=master)](https://inch-ci.org/github/david942j/seccomp-tools)
[![Yard Docs](http://img.shields.io/badge/yard-docs-blue.svg)](https://www.rubydoc.info/github/david942j/seccomp-tools/)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

# Seccomp Tools
Powerful tools for seccomp analysis.

This project is aimed primarily (but not exclusively) at analyzing seccomp sandboxes in CTF pwn challenges.
Some features are CTF-specific, but they're just as useful for analyzing real-world seccomp filters.

## Features
* Dump - Automatically dumps seccomp BPF from executables.
* Disasm - Converts seccomp BPF to a human-readable format.
  - With simple decompilation.
  - With syscall names and arguments whenever possible.
  - Colorful!
* Asm - Makes writing seccomp rules as easy as writing code.
* Emu - Emulates seccomp rules.
* Explain - Summarizes a filter as a per-action policy (which syscalls are allowed/killed, and when).
* Audit - Scans a filter for weaknesses and escape routes (missing arch/x32 guards, dangerous syscalls, ...).
* Multi-architecture support.

## Installation

Available on RubyGems.org!
```
$ gem install seccomp-tools
```

If compilation fails, try:
```
sudo apt install gcc ruby-dev make
```
then install seccomp-tools again.

## Command Line Interface

### seccomp-tools

```bash
SHELL_OUTPUT_OF(seccomp-tools --help)
SHELL_OUTPUT_OF(seccomp-tools dump --help)
```

### dump

Dumps the seccomp BPF from an executable, using the `ptrace` syscall.

NOTE: the target executable is actually run, so be careful with untrusted binaries.
```bash
SHELL_OUTPUT_OF(file spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f inspect)
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f raw | xxd)
```

### disasm

Disassembles raw seccomp BPF into a readable format.
```bash
SHELL_OUTPUT_OF(xxd spec/data/twctf-2016-diary.bpf | head -n 3)
SHELL_OUTPUT_OF(seccomp-tools disasm spec/data/twctf-2016-diary.bpf)
```

### asm

Assembles seccomp rules into raw bytes.
Useful when you want to write your own seccomp rules.

Supports jump labels and syscall names. See the examples below.
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

Since v1.6.0 [not released yet], `asm` has switched to a yacc-based parser, which allows a more flexible and intuitive syntax!

```bash
SHELL_OUTPUT_OF(cat spec/data/example.asm)
SHELL_OUTPUT_OF(seccomp-tools asm spec/data/example.asm -f raw | seccomp-tools disasm -)
```

The output of `seccomp-tools disasm <file> --asm-able` is valid input for `asm`:
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

### Explain

Summarizes a whole filter as a per-action policy: which syscalls end in `ALLOW`, `KILL`, `ERRNO`, etc.,
and under what argument constraints. The input can be a dumped BPF file, an executable (its seccomp is
dumped first, like `dump`), or a running process via `--pid`.
```bash
SHELL_OUTPUT_OF(seccomp-tools explain --help)
SHELL_OUTPUT_OF(seccomp-tools explain spec/data/libseccomp.bpf -a amd64)
```

A more involved example - the 0CTF/TCTF 2023 "Nothing is True" filter, which has separate 32/64-bit
allowlists and argument checks on `open`, `mmap` and `execve`:
```bash
SHELL_OUTPUT_OF(seccomp-tools explain spec/data/tctf-2023-nothing-is-true.bpf -a amd64)
```

### Audit

Scans a filter for weaknesses and likely escape routes - a missing architecture or x32 guard, a
permissive (denylist) default, equivalent-syscall gaps (e.g. `execve` blocked but `execveat` not),
an open/read/write chain, or dangerous syscalls reachable as `ALLOW` - and reports each with a
severity. It runs on every supported architecture (architecture-specific quirks like amd64's x32 are
applied only where they exist), and takes the same input as `explain` (a BPF file, an executable, or
`--pid`).
```bash
SHELL_OUTPUT_OF(seccomp-tools audit --help)
```

Auditing a denylist with several escape routes (the TokyoWesterns CTF 2016 "diary" filter):
```bash
SHELL_OUTPUT_OF(seccomp-tools audit spec/data/twctf-2016-diary.bpf -a amd64)
```

Use `--format json` for CI or tooling:
```bash
SHELL_OUTPUT_OF(seccomp-tools audit spec/data/gctf-2019-quals-caas.bpf -a amd64 -f json)
```

## Shell Completion

`seccomp-tools completion <bash|zsh|fish>` prints a completion script for the given shell. Load it from your shell's startup file:

```bash
# bash (~/.bashrc)
eval "$(seccomp-tools completion bash)"

# zsh (~/.zshrc, after `compinit`)
eval "$(seccomp-tools completion zsh)"

# fish (~/.config/fish/config.fish)
seccomp-tools completion fish | source
```

To avoid the startup cost of evaluating it every time, write the script to the directory your shell loads completions from instead, e.g. `seccomp-tools completion zsh > "${fpath[1]}/_seccomp-tools"`.

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
- [x] riscv64

Pull requests adding support for more architectures are welcome!

## Development

I recommend using [rbenv](https://github.com/rbenv/rbenv) to manage your Ruby environment.

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
And if you like this project, consider giving it a [star](https://github.com/david942j/seccomp-tools/stargazers) :grimacing:
