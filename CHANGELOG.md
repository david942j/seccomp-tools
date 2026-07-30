# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `explain` command: summarize a whole filter as a per-action policy (which syscalls end in ALLOW/KILL/ERRNO, and under what argument constraints).
- `audit` command: scan a filter for weaknesses and escape routes (missing architecture or x32 guard, permissive default, equivalent-syscall gaps, an open/read/write chain, dangerous syscalls reachable as ALLOW), with a `--format json` output.
- RISC-V 64 (`riscv64`) architecture support across dump, disasm, asm and emu.
- `dump --timeout SEC` to bound how long a traced program runs.
- `dump` now handles `SECCOMP_MODE_STRICT`, emitting the equivalent filter (strict mode installs no BPF of its own).

### Changed
- disasm, emu and asm now share a symbolic BPF execution engine; disasm names arguments by the architecture inferred from the filter rather than the one declared on the command line.
- `dump --pid` detects the target process's architecture (from its ELF header) instead of assuming the host's, so syscalls of a process built for another architecture are labelled correctly.
- `dump`'s `-c`/`--sh-exec` now takes precedence over a positional executable.
- `dump` warns when it finds no seccomp filter instead of printing nothing.
- Commands that need an architecture now fail with a clear message when the host architecture cannot be detected and no `--arch` was given, instead of erroring deep inside a syscall-table lookup.
- Colorized syscall names, gave warnings and info messages a color, and wrapped audit findings to 120 columns.

### Fixed
- Corrected 64-bit argument word order on big-endian (s390x) targets.
- Fixed the disassembly of seccomp return actions via a shared action-label decoder.
- The emulator now models division by zero as the kernel does (aborting the program with a kill) instead of raising.
- Fixed a Bundler error on Ruby head.

## [1.6.2] - 2025-11-23

### Added
- Ruby 3.4 support.
- `-i`/`--ip` option to set the instruction pointer in emulation mode.

### Changed
- Raised the minimum Ruby version to 3.1 (dropped 3.0).
- Declared `logger` as an explicit dependency (it is no longer a default gem).

### Fixed
- Bundled the license file and a missing runtime dependency in the gem.

## [1.6.1] - 2023-12-25

### Fixed
- Stopped raising an error on a long direct jump.
- Fixed wrong decompilation when the compiler optimized two branches to the same jump target.

## [1.6.0] - 2023-09-19

### Added
- Rewrote the `asm` assembler on a yacc (racc) based grammar, supporting a more flexible and intuitive syntax.
- `disasm --asm-able` to emit output that is valid input for `asm`.
- `disasm --no-bpf` to hide the raw BPF bytes.
- `<arch>.<syscall>` syntax in disasm and asm.
- Support for `!` (bang) in `if` conditions.
- Dumping seccomp filters on s390x.

### Changed
- Raise an error when a jump distance exceeds 255.
- Sped up the assembler's scanner.

## [1.5.0] - 2021-03-07

### Added
- x32 syscall support.
- Dumping seccomp filters on aarch64.
- Additional seccomp return actions.
- Syscall-name aliases matching `ausyscall`.

### Changed
- Skip the (Linux-only) dump functionality gracefully when installing on macOS.
- Migrated CI from Travis to GitHub Actions.

## [1.4.0] - 2020-02-16

### Added
- Dumping seccomp filters from an existing process (`dump --pid`).
- `A = -A` (negate) assembler syntax.
- An internal logger.

### Changed
- Upgraded dependencies and dropped Ruby 2.3.

## [1.3.0] - 2019-06-23

### Added
- Display of syscall arguments in the disassembly.
- Support a syscall name (not just a number) in the emulator.
- `c_source` and x86 `assembly` output formats for `asm`.
- Assembler support for `mem[]`, `len`, and absolute jumps.
- `sys_seccomp` on i386.

### Fixed
- A wrong regular expression in the tokenizer, and several reported bugs (#53, #54, #55).

### Changed
- Dropped an end-of-life Ruby version (2.2).

## [1.2.0] - 2018-04-05

### Added
- `KILL_PROCESS` return action.
- `ARCH_X86_64` in the assembler.
- The `seccomp` syscall introduced in Linux 3.17.

## [1.1.1] - 2017-12-01

### Added
- Show `errno` in the disassembly of an ERRNO return.
- Assembler support for `st`/`stx`.

### Fixed
- `lsh`/`rsh` in the assembler.

### Changed
- More meaningful error messages.

## [1.1.0] - 2017-09-29

### Added
- `asm` command: a seccomp BPF assembler.

## [1.0.0] - 2017-06-10

### Added
- `emu` command: emulate seccomp rules against a hypothetical syscall.

### Fixed
- Branch handling in the disassembler.

## [0.1.0] - 2017-06-08

### Added
- Initial release: the `dump` and `disasm` commands, ptrace-based dumping with `--limit` and `--output`, and i386 support.

[Unreleased]: https://github.com/david942j/seccomp-tools/compare/v1.6.2...HEAD
[1.6.2]: https://github.com/david942j/seccomp-tools/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/david942j/seccomp-tools/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/david942j/seccomp-tools/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/david942j/seccomp-tools/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/david942j/seccomp-tools/compare/1.3.0...v1.4.0
[1.3.0]: https://github.com/david942j/seccomp-tools/compare/v1.2.0...1.3.0
[1.2.0]: https://github.com/david942j/seccomp-tools/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/david942j/seccomp-tools/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/david942j/seccomp-tools/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/david942j/seccomp-tools/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/david942j/seccomp-tools/releases/tag/v0.1.0
