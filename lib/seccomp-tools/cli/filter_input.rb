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

      # Registers the options every command taking its filter from a process shares - +-c/--sh-exec+,
      # +-l/--limit+, +-p/--pid+ and +-t/--timeout+ - and their defaults, so the four stay described
      # and parsed the same way wherever they appear. The counterpart of {Base#option_arch}.
      # @param [OptionParser] opt
      # @param [String] action
      #   What the command does with each filter, woven into the descriptions.
      # @param [Hash{Symbol => Array<String>}] extra
      #   Extra description lines for one option, keyed by +:sh_exec+, +:limit+, +:pid+ or +:timeout+.
      # @return [void]
      # @example
      #   option_filter_source(opt, 'explain')
      #   option_filter_source(opt, 'dump', timeout: ['This option is ignored when --pid is given.'])
      def option_filter_source(opt, action, extra = {})
        option[:limit] = 1
        opt.on('-c', '--sh-exec <command>', "Executes the given command (via sh) and #{action}s its seccomp.",
               'Use this to pass arguments or pipe things to the execution file.',
               *extra[:sh_exec]) { |command| option[:command] = command }

        opt.on('-l', '--limit LIMIT', Integer, "#{action.capitalize} only the first LIMIT installed filters.",
               'Only meaningful when the input is an executable or --pid. Default: 1',
               *extra[:limit]) { |l| option[:limit] = l }

        opt.on('-p', '--pid PID', Integer, "#{action.capitalize} the seccomp filters installed on an existing process.",
               'You must have CAP_SYS_ADMIN (e.g. be root) to use this option.',
               *extra[:pid]) { |p| option[:pid] = p }

        opt.on('-t', '--timeout SEC', Float, 'Timeout (seconds) for the execution. Default: no timeout',
               *extra[:timeout]) { |t| option[:timeout] = t }
      end

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
      # the command accepts blobs at all, no +-c+ was given, and the positional argument is not an
      # executable (a plain file or stdin).
      # @return [Boolean]
      def raw_bpf_file?
        accepts_raw_bpf? && !option[:command] && !executable?(option[:ifile])
      end

      # Does a positional argument that is not an ELF mean "read this filter"? True for the commands
      # that analyze a filter ({Explain}, {Audit}); {Dump} overrides it to +false+, because its
      # positional is always something to execute - a shell script is not an ELF but must still be
      # run, not parsed as BPF.
      # @return [Boolean]
      def accepts_raw_bpf?
        true
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
