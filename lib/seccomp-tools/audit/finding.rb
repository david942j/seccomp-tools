# frozen_string_literal: true

module SeccompTools
  class Audit
    # Severities, most to least severe. Drives ordering and (for +human+ output) coloring.
    SEVERITIES = %i[high medium low].freeze

    # One weakness reported by a {Check}: a stable +id+, a +severity+, a human +title+/+detail+, the
    # architecture it applies to, the syscalls involved, an optional argument +condition+ under which
    # it holds, and a one-line +remediation+.
    Finding = Struct.new(:id, :severity, :title, :detail, :arch, :syscalls, :condition, :remediation,
                         keyword_init: true) do
      # Sort key: by severity, then id, then the affected syscalls.
      # @return [Array]
      def rank
        [SEVERITIES.index(severity) || SEVERITIES.size, id, Array(syscalls).join(',')]
      end

      # @return [Hash] JSON-ready shape.
      def to_h
        { id:, severity:, title:, detail:, arch:, syscalls: Array(syscalls), condition:, remediation: }
      end
    end
  end
end
