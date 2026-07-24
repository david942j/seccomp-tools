# frozen_string_literal: true

require 'seccomp-tools/cli/dumpable'
require 'seccomp-tools/logger'
require 'seccomp-tools/util'

module SeccompTools
  module CLI
    # Shared input handling for the commands that take a seccomp filter from a BPF file, stdin, an
    # executable, or a running process ({Explain} and {Audit}): it resolves the positional argument
    # and options into +[raw_bpf, arch, source]+ tuples, dumping via ptrace ({Dumpable}) when the
    # input is a command or +--pid+. The including command must provide +option+, +argv+, +parser+,
    # +input+ and +warn_ignored_arguments+ (all from {Base}).
    module FilterInput
      include Dumpable

      private

      # Resolves the input into an array of +[raw_bpf, arch, source]+ tuples, empty when there is
      # nothing to process (help shown, or an error was logged).
      #
      # The input is one of three kinds:
      # * a running process, when +--pid+ is given;
      # * a raw BPF file (or stdin), when the positional argument is not an executable;
      # * a command to run and trace - either +-c+, or a positional executable.
      # @return [Array<Array(String, Symbol, String?)>]
      def collect_filters
        # -c/--sh-exec and --pid take precedence over a positional BPF file or executable.
        option[:ifile] = argv.shift unless option[:command] || option[:pid]
        warn_ignored_arguments

        return dump_filters(command: nil, pid: option[:pid], source: "pid #{option[:pid]}") if option[:pid]

        command = option[:command] || option[:ifile]
        if command.nil? # nothing to process
          CLI.show(parser.help)
          return []
        end
        return read_raw_bpf if raw_bpf_file?

        dump_filters(command:, pid: nil, source: command)
      end

      # Reads the positional file (or stdin) as a raw BPF blob, logging an error instead of
      # crashing when it cannot be read.
      # @return [Array<Array(String, Symbol, String?)>]
      def read_raw_bpf
        [[input, option[:arch], source_name(option[:ifile])]]
      rescue SystemCallError => e
        Logger.error(e.message)
        []
      end

      # Should the input be read directly as a raw BPF blob, rather than run as a command? True when
      # no +-c+ was given and the positional argument is not an executable (a plain file or stdin).
      # @return [Boolean]
      def raw_bpf_file?
        !option[:command] && !executable?(option[:ifile])
      end

      # Dumps filters from a command or pid and labels each with +source+.
      # @return [Array<Array(String, Symbol, String?)>]
      #   The filter tuples, empty when dumping is unsupported or nothing was installed.
      def dump_filters(command:, pid:, source:)
        return [] unless dumping_supported?

        dump_seccomp(command:, pid:, limit: option[:limit], timeout: option[:timeout]) do |bpf, arch|
          [bpf, arch || option[:arch], source]
        end
      end

      # Is +file+ an ELF executable to run, rather than a raw BPF blob or stdin to read?
      # @param [String?] file
      #   The path to check. +nil+ (no argument) and +-+ (stdin) are not executables.
      # @return [Boolean]
      def executable?(file)
        file && file != '-' && Util.elf?(file)
      end

      # The label shown in the header for +file+; +<STDIN>+ when reading from stdin.
      # @param [String] file
      #   The input path, or +-+ for stdin.
      # @return [String]
      def source_name(file)
        file == '-' ? '<STDIN>' : file
      end
    end
  end
end
