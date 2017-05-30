require 'seccomp-tools/bpf'

module SeccompTools
  # Disassembler of seccomp bpf.
  module Disasm
    module_function

    # Disassemble bpf codes.
    # @param [String] bpf
    #   The bpf codes.
    # @todo
    #   Pass +arch+ as argument. (To support show syscall name)
    def disasm(bpf)
      codes = bpf.scan(/.{8}/m).map.with_index { |b, i| BPF.new(b, i) }
      <<EOS + codes.map(&:disasm).join("\n") + "\n"
 line  CODE  JT   JF      K
=================================
EOS
    end
  end
end
