# frozen_string_literal: true

require 'optparse'

require 'seccomp-tools/logger'
require 'seccomp-tools/util'

module SeccompTools
  module CLI
    # Base class for handlers.
    #
    # Each subcommand is a subclass that defines a +USAGE+ constant and a +parser+, and overrides
    # {#handle} to do its work.
    class Base
      # @return [{Symbol => Object}]
      #   Options parsed from the command line. Common keys are +:arch+, +:ifile+, +:ofile+,
      #   +:format+, +:limit+, +:pid+ and +:verbose+, depending on the subcommand.
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

      # Parses the common options, and shows the help message when asked to.
      # @return [Boolean]
      #   For descendants to check whether they need to continue. +false+ when the help message
      #   was shown and there is nothing left to do.
      def handle
        return CLI.show(parser.help) if argv.empty? || %w[-h --help].intersect?(argv)

        parser.parse!(argv)
        option[:arch] ||= Util.system_arch
        true
      end

      # If +option[:ifile]+ is '-', read from stdin,
      # otherwise, read from file.
      # @return [String]
      #   String read from file.
      def input
        option[:ifile] == '-' ? $stdin.read.force_encoding('ascii-8bit') : File.binread(option[:ifile])
      end

      # Write data to stdout or file(s).
      #
      # When +option[:ofile]+ is set, each call writes to a new file named after it with an
      # incrementing serial number, see {#file_of}. Colors are disabled while writing to a file.
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
        File.binwrite(file_of(option[:ofile], @serial), yield)
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

      # For descendants to define usage message easily.
      # @return [String]
      #   Usage information.
      def usage
        self.class.const_get(:USAGE)
      end

      # Warns about positional arguments left over in {#argv} after the command has taken what it
      # needs, e.g. an exec given together with +-c+, or anything after +--pid+. The command still
      # proceeds.
      # @return [void]
      def warn_ignored_arguments
        return if argv.empty?

        Logger.warn("ignoring unused argument#{'s' if argv.size > 1}: #{argv.join(' ')}")
      end

      # Registers the common +--arch+ option on +opt+.
      #
      # @param [OptionParser] opt
      #   The parser to add the option to.
      # @return [void]
      def option_arch(opt)
        supported = Util.supported_archs
        opt.on('-a', '--arch ARCH', supported, 'Specify architecture.',
               "Supported architectures are <#{supported.join('|')}>.",
               "Default: #{Util.system_arch}") do |a|
          option[:arch] = a
        end
      end
    end
  end
end
