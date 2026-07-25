# frozen_string_literal: true

require 'seccomp-tools/audit/catalog'
require 'seccomp-tools/audit/finding'

module SeccompTools
  class Audit
    module Checks
      # A syscall a sandbox almost never wants ({Catalog#dangerous}) is reachable as +ALLOW+. One
      # finding per syscall, carrying the argument condition (if any) under which it is allowed.
      module DangerousAllow
        module_function

        # @param [Audit::Policy] policy
        # @return [Array<Audit::Finding>]
        def call(policy)
          Catalog.dangerous(policy.arch_sym).filter_map do |name, meta|
            nr = policy.number(name)
            next unless nr && policy.reachable_as_allow?(nr)

            cond = policy.condition_for(nr)
            Finding.new(
              id: 'dangerous-allow', severity: meta[:severity], arch: policy.arch_name,
              title: "#{name} is allowed",
              detail: "#{name} reaches ALLOW - #{meta[:why]}.",
              syscalls: [name.to_s], condition: cond,
              remediation: "Block #{name} unless the program genuinely needs it."
            )
          end
        end
      end
    end
  end
end
