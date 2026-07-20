# frozen_string_literal: true

require 'seccomp-tools/explain/summary'
require 'seccomp-tools/symbolic/symbolic'

module SeccompTools
  # Analyzes a whole seccomp filter across all execution paths and summarizes it as a per-action
  # policy: which syscalls end in +ALLOW+, +KILL+, +ERRNO(n)+, etc., and under what argument
  # constraints.
  #
  # It runs the generic {Symbolic::Executor} over the filter to collect every reachable +return+
  # together with the path condition that leads to it, then hands those leaves to {Summary}, which
  # interprets them with seccomp semantics (syscall numbers, architectures, actions, ...).
  #
  # @example
  #   insts = SeccompTools::Disasm.to_bpf(raw, :amd64).map(&:inst)
  #   puts SeccompTools::Explain.new(insts, arch: :amd64).summarize
  class Explain
    # @param [Array<Instruction::Base>] instructions
    #   The filter, as +SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)+.
    # @param [Symbol] arch
    #   The architecture the filter is written for, used for syscall/argument names.
    # @param [String?] source
    #   A label for the filter (e.g. a filename) shown in the summary header.
    def initialize(instructions, arch:, source: nil)
      @instructions = instructions
      @arch = arch
      @source = source
    end

    # Walks the filter and returns a printable {Summary}.
    # @return [Summary]
    def summarize
      leaves, truncated = Symbolic::Executor.new(@instructions).run
      Summary.new(leaves, arch: @arch, source: @source, truncated:)
    end
  end
end
