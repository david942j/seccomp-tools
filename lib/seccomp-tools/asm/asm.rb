# frozen_string_literal: true

require 'seccomp-tools/asm/compiler'
require 'seccomp-tools/util'

module SeccompTools
  # Assembler of seccomp bpf.
  module Asm
    module_function

    # Assembler of seccomp bpf.
    # @param [String] str
    # @param [String] filename
    #   Only used for error messages.
    # @param [Symbol?] arch
    # @return [String]
    #   Raw BPF bytes.
    # @example
    #   SeccompTools::Asm.asm(<<-EOS)
    #     # lines start with '#' are comments
    #     A = sys_number                # here's a comment, too
    #     A >= 0x40000000 ? dead : next # 'next' is a keyword, denote the next instruction
    #     A == read ? ok : next         # custom defined label 'dead' and 'ok'
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
