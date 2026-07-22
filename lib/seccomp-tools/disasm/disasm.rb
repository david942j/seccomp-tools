# frozen_string_literal: true

require 'set'

require 'seccomp-tools/bpf'
require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/state'
require 'seccomp-tools/util'

module SeccompTools
  # Disassembler of seccomp BPF.
  module Disasm
    module_function

    # Disassemble BPF codes.
    #
    # Emulates the filter to track what each register holds, so syscall names and argument
    # positions can be inferred and shown as comments.
    # @param [String] raw
    #   The raw BPF bytes.
    # @param [Symbol?] arch
    #   Target architecture, must be one of {SeccompTools::Util.supported_archs}.
    #   Defaults to {SeccompTools::Util.system_arch} when +nil+.
    # @param [Boolean] display_bpf
    #   Whether to prepend each line with its raw +code+, +jt+, +jf+ and +k+ fields.
    # @param [Boolean] arg_infer
    #   Whether to annotate lines with the inferred syscall name and argument.
    # @return [String]
    #   The disassembly result, ready to be printed.
    # @example
    #   SeccompTools::Disasm.disasm(raw, arch: :amd64, display_bpf: false)
    #   #=> "0000: A = sys_number\n0001: if (A == read) goto 0003\n0002: return KILL\n0003: return ALLOW\n"
    def disasm(raw, arch: nil, display_bpf: true, arg_infer: true)
      codes = to_bpf(raw, arch)
      states = Array.new(codes.size) { Set.new }
      states[0].add(Symbolic::State.initial)
      # A forward pass (jumps only go forward) tracking, per line, the states that can reach it, so
      # syscall names and argument positions can be inferred from what each register holds. Unlike
      # the Executor, this over-approximates — it forks every conditional instead of folding — so
      # dead lines are still rendered.
      dis = codes.zip(states).map do |code, sts|
        sts.each do |st|
          code.branch(st) do |pc, s|
            states[pc].add(s) unless pc >= states.size
          end
        end
        code.states = sts
        code.disasm(code: display_bpf, arg_infer:)
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
    #   The raw BPF bytes, each instruction being 8 bytes long.
    # @param [Symbol?] arch
    #   Target architecture, defaults to {SeccompTools::Util.system_arch} when +nil+.
    # @return [Array<BPF>]
    #   One {BPF} per instruction, in order.
    def to_bpf(raw, arch)
      arch ||= Util.system_arch
      raw.scan(/.{8}/m).map.with_index { |b, i| BPF.new(b, arch, i) }
    end
  end
end
