# frozen_string_literal: true

require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/explain'

module SeccompTools
  module CLI
    # Handle 'explain' command.
    class Explain < Base
      # Summary of this command.
      SUMMARY = 'Summarize a seccomp filter as a per-action policy.'
      # Usage of this command.
      USAGE = "explain - #{SUMMARY}\n\nUsage: seccomp-tools explain [options] BPF_FILE".freeze

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage

          option_arch(opt)
        end
      end

      # Analyzes the filter and prints the resulting policy.
      # @return [void]
      def handle
        return unless super

        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:ifile].nil?

        insts = SeccompTools::Disasm.to_bpf(input, option[:arch]).map(&:inst)
        output do
          SeccompTools::Explain.new(insts, arch: option[:arch], source: source_name).summarize.to_s
        end
      end

      private

      # The label shown in the policy header, +nil+ when reading from stdin.
      # @return [String?]
      def source_name
        option[:ifile] == '-' ? nil : option[:ifile]
      end
    end
  end
end
