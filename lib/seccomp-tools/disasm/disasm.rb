require 'set'

require 'seccomp-tools/bpf'
require 'seccomp-tools/disasm/context'
require 'seccomp-tools/util'

module SeccompTools
  # Disassembler of seccomp bpf.
  module Disasm
    module_function

    # Disassemble bpf codes.
    # @param [String] raw
    #   The raw bpf bytes.
    # @param [Symbol] arch
    #   Architecture.
    def disasm(raw, arch: nil)
      codes = to_bpf(raw, arch)
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

    # Convert raw bpf string to array of {BPF}.
    # @param [String] raw
    # @param [Symbol] arch
    # @return [Array<BPF>]
    def to_bpf(raw, arch)
      arch ||= Util.system_arch
      raw.scan(/.{8}/m).map.with_index { |b, i| BPF.new(b, arch, i) }
    end
  end
end
