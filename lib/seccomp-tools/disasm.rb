require 'seccomp-tools/bpf'
require 'seccomp-tools/context'
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
    # @todo
    #   Detect system architecture as default.
    def disasm(bpf, arch: nil)
      arch ||= Util.system_arch
      codes = bpf.scan(/.{8}/m).map.with_index { |b, i| BPF.new(b, arch, i) }
      contexts = Array.new(codes.size) { [] }
      contexts[0].push(Context.new)
      dis = codes.zip(contexts).map do |code, ctxs|
        ctxs.each do |ctx|
          code.branch(ctx) do |pc, c|
            contexts[pc].push(c) unless c.nil? || pc >= contexts.size
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
