# frozen_string_literal: true

require 'seccomp-tools/cli/base'
require 'seccomp-tools/logger'

module SeccompTools
  module CLI
    # Handle 'completion' command.
    class Completion < Base
      # Summary of this command.
      SUMMARY = 'Print a shell completion script.'
      # Usage of this command.
      USAGE = "completion - #{SUMMARY}\n\nUsage: seccomp-tools completion <bash|zsh|fish>".freeze

      # Maps a shell name to the completion script that ships with the gem.
      SCRIPTS = { 'bash' => 'seccomp-tools.bash', 'zsh' => '_seccomp-tools', 'fish' => 'seccomp-tools.fish' }.freeze

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
        end
      end

      # Writes the completion script for the requested shell to stdout.
      # @return [void]
      def handle
        return unless super

        shell = argv.shift
        file = SCRIPTS[shell]
        return CLI.show(parser.help) if file.nil?

        output { File.read(File.join(__dir__, '..', '..', '..', 'completions', file)) }
      end
    end
  end
end
