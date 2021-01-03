# frozen_string_literal: true

# @author david942j

# Main module.
module SeccompTools
end

require 'os'
require 'seccomp-tools/asm/asm'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/dumper' if OS.linux?
require 'seccomp-tools/emulator'
require 'seccomp-tools/version'
