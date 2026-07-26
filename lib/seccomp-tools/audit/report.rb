# frozen_string_literal: true

require 'seccomp-tools/audit/finding'
require 'seccomp-tools/util'

module SeccompTools
  class Audit
    # The findings for one filter, rendered either as a human report or a JSON-ready hash.
    class Report
      # Severity => {Util.colorize} theme for the +[SEVERITY]+ tag.
      SEVERITY_THEME = { high: :error, medium: :warn, low: :info }.freeze

      # @param [String?] source Label for the audited filter.
      # @param [Array<String>] arches The architectures covered.
      # @param [Array<Finding>] findings
      # @param [Boolean] truncated Whether the symbolic walk was cut short.
      def initialize(source:, arches:, findings:, truncated:)
        @source = source
        @arches = arches
        @findings = findings.sort_by(&:rank)
        @truncated = truncated
      end

      # @return [Array<Finding>]
      attr_reader :findings
      # @return [Array<String>] The architectures covered.
      attr_reader :arches

      # The human report.
      # @return [String]
      def to_s
        out = +''
        out << "Seccomp audit of #{@source}\n" if @source
        out << "Architectures: #{@arches.join(', ')}\n" unless @arches.empty?
        # A truncated walk can only hide weaknesses, so it qualifies the whole report rather than
        # being a finding of its own.
        out << "WARNING: analysis truncated (filter too large); results may be incomplete.\n" if @truncated
        return out << "\nNo weaknesses found.\n" if @findings.empty?

        @findings.each { |f| out << render(f) }
        out
      end

      # @return [Hash] JSON-ready shape for one filter.
      def to_h
        { source: @source, arches: @arches, truncated: @truncated, findings: @findings.map(&:to_h) }
      end

      private

      def render(finding)
        tag = Util.colorize("[#{finding.severity.to_s.upcase}]", t: SEVERITY_THEME[finding.severity])
        arch = finding.arch ? " (#{Util.colorize(finding.arch, t: :arch)})" : ''
        out = "\n#{tag} #{finding.title}#{arch}\n"
        out << "    #{finding.detail}\n"
        out << "    when: #{finding.condition}\n" if finding.condition
        out << "    fix:  #{finding.remediation}\n" if finding.remediation
        out
      end
    end
  end
end
