require 'seccomp-tools/asm/compiler'
require 'seccomp-tools/util'

module SeccompTools
  # Assembler of seccomp bpf.
  module Asm
    module_function

    # Assembler of seccomp bpf.
    # @param [String] str
    # @return [String]
    #   Raw bpf bytes.
    # @example
    #   asm(<<EOS)
    #     # lines start with '#' are comments
    #     A = sys_number                # here's a comment, too
    #     A >= 0x40000000 ? dead : next # 'next' is a keyword, denote the next instruction
    #     A == read ? ok : next         # custom defined label 'dead' and 'ok'
    #     A == 1 ? ok : next            # SYS_write = 1 in amd64
    #     return ERRNO(1)
    #     dead:
    #     return KILL
    #     ok:
    #     return ALLOW
    #   EOS
    #   #=> <raw binary bytes>
    def asm(str, arch: nil)
      arch = Util.system_arch if arch.nil? # TODO: show warning
      compiler = Compiler.new(arch)
      str.lines.each { |l| compiler.process(l) }
      compiler.compile!.map(&:asm).join
    end
  end
end
