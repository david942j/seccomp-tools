# frozen_string_literal: true

require 'seccomp-tools/audit/catalog'
require 'seccomp-tools/audit/finding'

module SeccompTools
  class Audit
    module Checks
      # An equivalent-syscall gap: a group member is singled out for denial while a sibling with the
      # same capability still reaches +ALLOW+ (blocked +execve+ but not +execveat+, +open+ but not
      # +openat+, +fork+ but not +clone+).
      module SyscallAltGap
        module_function

        # @param [Audit::Policy] policy
        # @return [Array<Audit::Finding>]
        def call(policy)
          Catalog.alt_groups(policy.arch_sym).filter_map do |group, names|
            present = names.filter_map { |n| [n, policy.number(n)] if policy.number(n) }
            denied = present.select { |_n, nr| policy.explicitly_denied?(nr) }.map(&:first)
            allowed = present.select { |_n, nr| policy.reachable_as_allow?(nr) }.map(&:first)
            next if denied.empty? || allowed.empty?

            finding(policy, group, denied, allowed)
          end
        end

        # @!visibility private
        def finding(policy, group, denied, allowed)
          Finding.new(
            id: 'syscall-alt-gap', severity: %i[exec open].include?(group) ? :high : :medium,
            arch: policy.arch_name,
            title: "#{denied.join('/')} blocked but #{allowed.join('/')} allowed",
            detail: "#{denied.join(', ')} denied, but the equivalent #{allowed.join(', ')} reaches " \
                    'ALLOW - same capability, different syscall number.',
            syscalls: allowed.map(&:to_s), condition: nil,
            remediation: "Deny every equivalent in the group: also block #{allowed.join(', ')}."
          )
        end
      end
    end
  end
end
