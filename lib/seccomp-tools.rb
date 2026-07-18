# frozen_string_literal: true

# @author david942j

# Toolkit for working with seccomp BPF filters.
#
# The library entry points are {Asm.asm} to compile assembly into raw BPF, {Disasm.disasm} to turn
# raw BPF back into readable assembly, {Dumper.dump} to capture the filters a process installs, and
# {Emulator} to run a filter against a hypothetical syscall.
#
# @example
#   raw = SeccompTools::Asm.asm("return ALLOW\n", arch: :amd64)
#   SeccompTools::Disasm.disasm(raw, arch: :amd64, display_bpf: false)
#   #=> "0000: return ALLOW\n"
module SeccompTools
end

require 'seccomp-tools/asm/asm'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/dumper'
require 'seccomp-tools/emulator'
require 'seccomp-tools/version'
