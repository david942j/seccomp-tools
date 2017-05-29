require 'seccomp-tools/cli/base'
require 'seccomp-tools/dumper'

module SeccompTools
  module CLI
    # Handle 'dump' command.
    class Dump < Base
      SUMMARY = 'Automatically dump seccomp bpf from execution file'.freeze

      def usage
        'Usage: seccomp-tools dump -c exec [options]'
      end

      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-e', '--exec <command>', 'Executes the given command') do |command|
            option[:command] = command
          end
        end
      end

      def handle(argv)
        return CLI.show(parser.help) if %w[-h --help].any? { |h| argv.include?(h) }
        parser.parse!(argv)
        raise ArgumentError, 'Option -e not present' if option[:command].nil?
      end
    end
  end
end
