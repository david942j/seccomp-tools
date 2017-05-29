[![Build Status](https://travis-ci.org/david942j/seccomp-tools.svg?branch=master)](https://travis-ci.org/david942j/seccomp-tools)
[![Code Climate](https://codeclimate.com/github/david942j/seccomp-tools/badges/gpa.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Issue Count](https://codeclimate.com/github/david942j/seccomp-tools/badges/issue_count.svg)](https://codeclimate.com/github/david942j/seccomp-tools)
[![Test Coverage](https://codeclimate.com/github/david942j/seccomp-tools/badges/coverage.svg)](https://codeclimate.com/github/david942j/seccomp-tools/coverage)
[![Inline docs](https://inch-ci.org/github/david942j/seccomp-tools.svg?branch=master)](https://inch-ci.org/github/david942j/seccomp-tools)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

# seccomp-tools
Provides powerful tools for seccomp analysis.

## Features
* (WIP) Automatically dump seccomp-bpf from binary.
* (TODO) Convert bpf to more readable format than libseccomp/tools.
* (TODO) Resolve constraints for syscalls (e.g. `execve/open/read/write`).
* (TODO) Support multi-architecture.

## Installation

(TODO)

## Command Line Interface

### seccomp-tools
```
SHELL_OUTPUT_OF(seccomp-tools)

SHELL_OUTPUT_OF(seccomp-tools help dump)
```

### dump
```
SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f inspect)

SHELL_OUTPUT_OF(seccomp-tools dump spec/binary/twctf-2016-diary -f raw | xxd)
```
