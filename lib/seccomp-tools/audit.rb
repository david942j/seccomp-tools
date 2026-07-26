# frozen_string_literal: true

require 'seccomp-tools/audit/checks'
require 'seccomp-tools/audit/policy'
require 'seccomp-tools/audit/report'
require 'seccomp-tools/explain/analysis'
require 'seccomp-tools/symbolic/executor'

module SeccompTools
  # Assesses a seccomp filter for weaknesses / escape routes and reports them as a {Audit::Report}.
  #
  # It runs the generic {Symbolic::Executor} over the filter (the same walk {Explain} uses), splits
  # the leaves per architecture with {Explain::Analysis}, and runs each {Checks} rule against the
  # per-arch {Policy}. Every supported architecture is assessed; architecture-specific quirks (e.g.
  # amd64's x32 ABI) are registered per arch in {Checks}, never special-cased inline.
  #
  # @example
  #   insts = SeccompTools::Disasm.to_bpf(raw, :amd64).map(&:inst)
  #   puts SeccompTools::Audit.new(insts, arch: :amd64, source: 'a.out').audit
  class Audit
    # @param [Array<Instruction::Base>] instructions
    #   The filter, as +SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)+.
    # @param [Symbol] arch
    #   The architecture the filter is written for, used when it does not itself branch on +arch+.
    # @param [String?] source
    #   A label for the filter (e.g. a filename) shown in the report.
    def initialize(instructions, arch:, source: nil)
      @instructions = instructions
      @arch = arch
      @source = source
    end

    # Walks the filter, runs every check, and returns the {Report}.
    # @return [Report]
    def audit
      leaves, truncated = Symbolic::Executor.new(@instructions).run
      analysis = Explain::Analysis.new(leaves)
      policies = analysis.sections(@arch).map { |section| Policy.new(analysis, section) }

      findings = Checks::FILTER.flat_map { |check| check.call(analysis) }
      policies.each do |policy|
        Checks.section_checks(policy.arch_sym).each { |check| findings.concat(check.call(policy)) }
      end

      Report.new(source: @source, arches: policies.map(&:arch_name), findings:, truncated:)
    end
  end
end
