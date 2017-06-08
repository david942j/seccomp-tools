require 'optparse'

module SeccompTools
  module CLI
    # Base class for handlers.
    class Base
      # @return [Hash{Symbol => Object}] Options.
      attr_reader :option
      # @return [Array<String>] Arguments array.
      attr_reader :argv

      # Instantiate a {Base} object.
      # @param [Array<String>] argv
      #   Arguments array.
      def initialize(argv)
        @option = {}
        @argv = argv
      end

      private

      # Handle show help message.
      # @return [Boolean]
      #   For decestors to check if needs to conitnue.
      def handle
        return CLI.show(parser.help) if argv.empty? || %w[-h --help].any? { |h| argv.include?(h) }
        parser.parse!(argv)
        true
      end

      # Write data to stdout or file(s).
      # @yieldreturn [String]
      #   The data to be written.
      # @return [void]
      def output
        # if file name not present, just output to stdout.
        return $stdout.write(yield) if option[:ofile].nil?
        # times of calling output
        @serial ||= 0
        # Write to file, we should disable colorize
        enabled = Util.colorize_enabled?
        Util.disable_color! if enabled
        IO.binwrite(file_of(option[:ofile], @serial), yield)
        Util.enable_color! if enabled
        @serial += 1
      end

      # Get filename with serial number.
      #
      # @param [String] file
      #   Filename.
      # @param [Integer] serial
      #   serial number, starts from zero.
      # @return [String]
      #   Result filename.
      # @example
      #   file_of('a.png', 0)
      #   #=> 'a.png'
      #   file_of('a.png', 1)
      #   #=> 'a_1.png'
      #   file_of('test/a.png', 3)
      #   #=> 'test/a_3.png'
      def file_of(file, serial)
        suffix = serial.zero? ? '' : "_#{serial}"
        ext = File.extname(file)
        base = File.basename(file, ext)
        File.join(File.dirname(file), base + suffix) + ext
      end

      # For decestors easy to define usage message.
      # @return [String]
      #   Usage information.
      def usage
        self.class.const_get(:USAGE)
      end
    end
  end
end
