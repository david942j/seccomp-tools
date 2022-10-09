# frozen_string_literal: true

require 'set'

require 'seccomp-tools/bpf'
require 'seccomp-tools/disasm/context'
require 'seccomp-tools/util'

module SeccompTools
  # Disassembler of seccomp BPF.
  module Disasm
    module_function

    # Disassemble BPF codes.
    # @param [String] raw
    #   The raw BPF bytes.
    # @param [Symbol] arch
    #   Architecture.
    # @param [Boolean] display_bpf
    # @param [Boolean] arg_infer
    def disasm(raw, arch: nil, display_bpf: true, arg_infer: true)
      codes = to_bpf(raw, arch)
      contexts = Array.new(codes.size) { Set.new }
      contexts[0].add(Context.new)
      # all we care is whether A is data[*]
      dis = codes.zip(contexts).map do |code, ctxs|
        ctxs.each do |ctx|
          code.branch(ctx) do |pc, c|
            contexts[pc].add(c) unless pc >= contexts.size
          end
        end
        code.contexts = ctxs
        code.disasm(code: display_bpf, arg_infer: arg_infer)
      end.join("\n")
      if display_bpf
        <<-EOS
 line  CODE  JT   JF      K
=================================
#{dis}
        EOS
      else
        "#{dis}\n"
      end
    end

    # Convert raw BPF string to array of {BPF}.
    # @param [String] raw
    # @param [Symbol] arch
    # @return [Array<BPF>]
    def to_bpf(raw, arch)
      arch ||= Util.system_arch
      raw.scan(/.{8}/m).map.with_index { |b, i| BPF.new(b, arch, i) }
    end
  end
end
