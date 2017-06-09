require 'set'

require 'seccomp-tools/bpf'
require 'seccomp-tools/disasm/context'
require 'seccomp-tools/util'

module SeccompTools
  # Disassembler of seccomp bpf.
  module Disasm
    module_function

    # Disassemble bpf codes.
    # @param [String] bpf
    #   The bpf codes.
    # @param [Symbol] arch
    #   Architecture.
    def disasm(bpf, arch: nil)
      arch ||= Util.system_arch
      codes = bpf.scan(/.{8}/m).map.with_index { |b, i| BPF.new(b, arch, i) }
      contexts = Array.new(codes.size) { Set.new }
      contexts[0].add(Context.new)
      # all we care is if A is exactly one of data[*]
      dis = codes.zip(contexts).map do |code, ctxs|
        ctxs.each do |ctx|
          code.branch(ctx) do |pc, c|
            contexts[pc].add(c) unless pc >= contexts.size
          end
        end
        code.contexts = ctxs
        code.disasm
      end.join("\n")
      <<EOS + dis + "\n"
 line  CODE  JT   JF      K
=================================
EOS
    end
  end
end
