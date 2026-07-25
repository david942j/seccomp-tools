# frozen_string_literal: true

require 'seccomp-tools/audit/finding'
require 'seccomp-tools/explain/verdict'

module SeccompTools
  class Audit
    module Checks
      # The filter does not validate the architecture, or lets an unlisted one reach +ALLOW+. Syscall
      # numbers are ABI-relative, so number-only rules are dodged by invoking under another ABI.
      module ArchUnchecked
        module_function

        # @param [Explain::Analysis] analysis
        # @return [Array<Audit::Finding>]
        def call(analysis)
          if analysis.arch_values.empty?
            [finding('Architecture is never validated',
                     'The filter checks syscall numbers without ever comparing data[4] (arch). ' \
                     'Numbers mean different syscalls under another AUDIT_ARCH, so the checks can be ' \
                     'dodged by invoking through a different ABI (e.g. i386 numbering on amd64).')]
          elsif analysis.other_leaves.any? { |l| Explain::Verdict.label(l.ret) == 'ALLOW' }
            [finding('Unlisted architectures reach ALLOW',
                     'Some paths reach ALLOW on an architecture the filter does not explicitly ' \
                     'check, so a different-ABI call can slip past the syscall-number rules.')]
          else
            []
          end
        end

        # @!visibility private
        def finding(title, detail)
          Finding.new(id: 'arch-unchecked', severity: :high, arch: nil, title:, detail:,
                      syscalls: [], condition: nil,
                      remediation: 'Compare data[4] against your AUDIT_ARCH_* and KILL every ' \
                                   'architecture you do not explicitly handle.')
        end
      end
    end
  end
end
