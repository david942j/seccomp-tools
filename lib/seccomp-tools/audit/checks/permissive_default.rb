# frozen_string_literal: true

require 'seccomp-tools/audit/finding'

module SeccompTools
  class Audit
    module Checks
      # The catch-all action is +ALLOW+: a denylist, bypassable by anything the author forgot.
      module PermissiveDefault
        module_function

        # @param [Audit::Policy] policy
        # @return [Array<Audit::Finding>]
        def call(policy)
          return [] unless policy.default_label == 'ALLOW'

          [Finding.new(
            id: 'permissive-default', severity: :high, arch: policy.arch_name,
            title: 'Default action is ALLOW (denylist)',
            detail: 'Any syscall the filter does not explicitly block is allowed; a denylist is ' \
                    'bypassable by any syscall the author overlooked.',
            syscalls: [], condition: nil,
            remediation: 'Use an allowlist: default to KILL/ERRNO and permit only the needed syscalls.'
          )]
        end
      end
    end
  end
end
