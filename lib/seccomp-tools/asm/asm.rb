# frozen_string_literal: true

require 'seccomp-tools/asm/compiler'
require 'seccomp-tools/util'

module SeccompTools
  # Assembler of seccomp bpf.
  module Asm
    module_function

    # Compiles seccomp assembly into raw BPF bytes.
    # @param [String] str
    #   The assembly source to be compiled.
    # @param [String] filename
    #   Only used for error messages.
    # @param [Symbol?] arch
    #   Target architecture, must be one of {SeccompTools::Util.supported_archs}.
    #   Defaults to {SeccompTools::Util.system_arch} when +nil+.
    # @return [String]
    #   Raw BPF bytes.
    # @raise [SeccompTools::Error]
    #   If +str+ is not valid seccomp assembly.
    # @example
    #   SeccompTools::Asm.asm(<<-EOS)
    #     # lines starting with '#' are comments
    #     A = sys_number                # here's a comment, too
    #     A >= 0x40000000 ? dead : next # 'next' is a keyword, denoting the next instruction
    #     A == read ? ok : next         # custom-defined labels 'dead' and 'ok'
    #     A == 1 ? ok : next            # SYS_write = 1 on amd64
    #     return ERRNO(1)
    #     dead:
    #     return KILL
    #     ok:
    #     return ALLOW
    #   EOS
    #   #=> <raw binary bytes>
    def asm(str, filename: '-', arch: nil)
      filename = nil if filename == '-'
      arch = Util.system_arch if arch.nil?
      compiler = Compiler.new(str, filename, arch)
      compiler.compile!.map(&:asm).join
    end
  end
end
