# frozen_string_literal: true

require 'seccomp-tools/audit/finding'
require 'seccomp-tools/util'

module SeccompTools
  class Audit
    # The findings for one filter, rendered either as a human report or a JSON-ready hash.
    class Report
      # Severity => {Util.colorize} theme for the +[SEVERITY]+ tag.
      SEVERITY_THEME = { high: :error, medium: :warn, low: :info }.freeze

      # Widest a rendered line may get, so a finding reads without wrapping on a standard terminal.
      WIDTH = 120

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
        names = finding.syscalls
        out = "\n#{tag} #{highlight(finding.title, names)}#{arch}\n"
        out << paragraph(finding.detail, names, '    ', '    ')
        out << paragraph(finding.condition, names, '    when: ', '          ') if finding.condition
        out << paragraph(finding.remediation, names, '    fix:  ', '          ') if finding.remediation
        out
      end

      # +text+ wrapped to {WIDTH} columns, its first line prefixed with +first+ and the rest with
      # +hang+ so they read as one block. Wrapping is measured before coloring, so the invisible
      # escape codes never count towards the width.
      # @return [String]
      def paragraph(text, names, first, hang)
        lines = []
        indent = first
        line = nil
        text.to_s.split(/\s+/).each do |word|
          if line.nil?
            line = word
          elsif indent.size + line.size + 1 + word.size <= WIDTH
            line = "#{line} #{word}"
          else
            lines << (indent + line)
            indent = hang
            line = word
          end
        end
        lines << (indent + line) if line
        lines.map { |l| "#{highlight(l, names)}\n" }.join
      end

      # Paints the syscall names a finding is about wherever they appear in +text+, in the same color
      # disasm gives them. Whole words only, so +read+ leaves +process_vm_readv+ alone.
      # @return [String]
      def highlight(text, names)
        Array(names).uniq.reduce(text) do |painted, name|
          painted.gsub(/\b#{Regexp.escape(name)}\b/) { Util.colorize(name, t: :syscall) }
        end
      end
    end
  end
end
