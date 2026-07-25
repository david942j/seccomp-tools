# frozen_string_literal: true

require 'seccomp-tools/audit/finding'

module SeccompTools
  class Audit
    module Checks
      # amd64's x32 ABI quirk: x32 syscalls share +AUDIT_ARCH_X86_64+ but number as +nr | 0x40000000+.
      # Without a +sys_number >= 0x40000000+ (or +jset 0x40000000+) guard, a syscall blocked by its
      # native number is still reachable through its x32 number. Registered only for amd64, so no
      # other architecture is ever mis-flagged.
      module X32Guard
        module_function

        # @param [Audit::Policy] policy
        # @return [Array<Audit::Finding>]
        def call(policy)
          sharp = policy.table.filter_map do |name, nr|
            next if name.to_s.start_with?('x32_')

            x = policy.number(:"x32_#{name}")
            name if x && policy.reachable_as_allow?(x) && !policy.reachable_as_allow?(nr)
          end
          return [] if sharp.empty?

          [finding(policy, sharp)]
        end

        # @!visibility private
        def finding(policy, sharp)
          shown = sharp.first(8).map(&:to_s)
          more = sharp.size > shown.size ? ", ... (+#{sharp.size - shown.size} more)" : ''
          Finding.new(
            id: 'x32-guard', severity: :high, arch: policy.arch_name,
            title: 'x32 ABI is not guarded',
            detail: 'Syscalls blocked by their native number are reachable via their x32 number ' \
                    "(nr | 0x40000000): #{shown.join(', ')}#{more}.",
            syscalls: shown, condition: nil,
            remediation: 'After the arch check, KILL when sys_number >= 0x40000000 ' \
                         '(or jset 0x40000000).'
          )
        end
      end
    end
  end
end
