# frozen_string_literal: true

require 'seccomp-tools/audit/catalog'
require 'seccomp-tools/audit/finding'

module SeccompTools
  class Audit
    module Checks
      # An open-family, a read-family and a write/send-family syscall are all reachable as +ALLOW+ -
      # the classic "open the flag, read it, write it out" chain.
      module OrwChain
        module_function

        # @param [Audit::Policy] policy
        # @return [Array<Audit::Finding>]
        def call(policy)
          o = first_allowed(policy, Catalog::ORW[:open])
          r = first_allowed(policy, Catalog::ORW[:read])
          w = first_allowed(policy, Catalog::ORW[:write])
          return [] unless o && r && w

          [Finding.new(
            id: 'orw-chain', severity: :high, arch: policy.arch_name,
            title: 'A file can be opened and its contents copied out',
            # The syscall names are painted wherever they appear, so keep them out of prose that
            # merely describes the actions - only name one where the syscall itself is meant.
            detail: "#{o}, #{r} and #{w} all reach ALLOW, so the contents of an arbitrary file " \
                    '(e.g. the flag) can be copied straight back out.',
            syscalls: [o, r, w].map(&:to_s), condition: nil,
            remediation: 'Deny the open-family syscalls unless the program genuinely needs arbitrary files.'
          )]
        end

        # @!visibility private
        def first_allowed(policy, names)
          names.find { |n| (nr = policy.number(n)) && policy.reachable_as_allow?(nr) }
        end
      end
    end
  end
end
