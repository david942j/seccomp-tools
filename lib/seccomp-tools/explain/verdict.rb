# frozen_string_literal: true

require 'seccomp-tools/const'

module SeccompTools
  class Explain
    # Decodes the value a filter path returns into the action it stands for: the label a policy
    # shows (+ALLOW+, +ERRNO(5)+, ...) and where that action sorts among the buckets.
    module Verdict
      # Buckets are printed in this order; unlisted actions sort last.
      ORDER = %i[ALLOW USER_NOTIF LOG TRACE TRAP ERRNO KILL KILL_PROCESS UNKNOWN].freeze

      module_function

      # The label for the value +ret+ a leaf returns, including the +SECCOMP_RET_DATA+ part when
      # it is meaningful for the action.
      # @param [Symbolic::Expr] ret
      # @return [String]
      def label(ret)
        return 'UNKNOWN' unless ret.imm?

        action = Const::BPF::ACTION.invert[ret.val & Const::BPF::SECCOMP_RET_ACTION_FULL]
        # An unrecognized action value loads fine; the kernel treats it as KILL_PROCESS
        # (KILL_THREAD before Linux 4.14). See seccomp(2).
        return format('KILL_PROCESS (unknown action 0x%x)', ret.val) if action.nil?

        data = ret.val & Const::BPF::SECCOMP_RET_DATA
        case action
        when :ERRNO then "ERRNO(#{data})"
        # TRACE's data reaches the tracer as the ptrace event message, TRAP's as si_errno of the
        # SIGSYS - both are part of the policy, so show them (when set; 0 is the idle default).
        when :TRACE, :TRAP then data.zero? ? action.to_s : "#{action}(#{data})"
        else action.to_s
        end
      end

      # Where the bucket labeled +label+ sorts: by its action's position in {ORDER}, then
      # alphabetically. Works on any label {.label} produces, data and annotations included.
      # @param [String] label
      # @return [Array(Integer, String)]
      def rank(label)
        action = label.sub(/\s*\(.*/, '').to_sym
        [ORDER.index(action) || ORDER.size, label]
      end
    end
  end
end
