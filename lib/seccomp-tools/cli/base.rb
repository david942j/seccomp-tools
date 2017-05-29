require 'optparse'

module SeccompTools
  module CLI
    # Base class for handlers.
    class Base
      attr_reader :option, :argv
      def initialize(argv)
        @option = {}
        @argv = argv
      end

      def handle
        return CLI.show(parser.help) if argv.empty? || %w[-h --help].any? { |h| argv.include?(h) }
        parser.parse!(argv)
        true
      end
    end
  end
end
