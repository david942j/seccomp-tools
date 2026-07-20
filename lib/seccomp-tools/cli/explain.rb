# frozen_string_literal: true

require 'seccomp-tools/cli/base'
require 'seccomp-tools/cli/dumpable'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/dumper'
require 'seccomp-tools/explain'
require 'seccomp-tools/logger'
require 'seccomp-tools/util'

module SeccompTools
  module CLI
    # Handle 'explain' command.
    class Explain < Base
      include Dumpable

      # Summary of this command.
      SUMMARY = 'Summarize a seccomp filter as a per-action policy.'
      # Usage of this command.
      USAGE = "explain - #{SUMMARY}\n\nUsage: seccomp-tools explain [options] [BPF_FILE|EXEC]".freeze

      # Instantiate an {Explain} object.
      #
      # Takes the same arguments as {Base#initialize}.
      def initialize(*)
        super
        option[:limit] = 1
        option[:pid] = nil
        option[:timeout] = nil
      end

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage

          option_arch(opt, 'With an executable or --pid the architecture is auto-detected instead.')

          opt.on('-c', '--sh-exec <command>', 'Executes the given command (via sh) and explains its seccomp.',
                 'Use this to pass arguments or pipe things to the execution file.') do |command|
            option[:command] = command
          end

          opt.on('-l', '--limit LIMIT', Integer, 'Explain only the first LIMIT installed filters.',
                 'Only meaningful when the input is an executable or --pid. Default: 1') do |l|
            option[:limit] = l
          end

          opt.on('-p', '--pid PID', Integer, 'Explain the seccomp filters installed on an existing process.',
                 'You must have CAP_SYS_ADMIN (e.g. be root) to use this option.') do |p|
            option[:pid] = p
          end

          opt.on('-t', '--timeout SEC', Float, 'Timeout (seconds) for the execution. Default: no timeout') do |t|
            option[:timeout] = t
          end
        end
      end

      # Reads the filter(s) from a BPF file, an executable, or an existing process, then prints the
      # policy of each.
      # @return [void]
      def handle
        return unless super

        filters = collect_filters
        if filters.size > 1
          Logger.warn("#{filters.size} filters are installed; they stack, so a syscall must pass every one " \
                      '(most restrictive wins). Each is explained separately below.')
        end
        filters.each_with_index do |(raw, arch, source), idx|
          label = filters.size > 1 ? "#{source} (filter ##{idx})" : source
          insts = SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)
          output { SeccompTools::Explain.new(insts, arch:, source: label).summarize.to_s }
        end
      end

      private

      # Resolves the input into an array of +[raw_bpf, arch, source]+ tuples, empty when there is
      # nothing to explain (help shown, or an error was logged).
      #
      # The input is one of three kinds:
      # * a running process, when +--pid+ is given;
      # * a raw BPF file (or stdin), when the positional argument is not an executable;
      # * a command to run and trace - either +-c+, or a positional executable.
      # @return [Array<Array(String, Symbol, String?)>]
      def collect_filters
        # -c/--sh-exec and --pid take precedence over a positional BPF file or executable.
        option[:ifile] = argv.shift if option[:command].nil? && option[:pid].nil?
        warn_ignored_arguments

        return dump_filters(command: nil, pid: option[:pid], source: "pid #{option[:pid]}") if option[:pid]

        if no_input?
          CLI.show(parser.help)
          return []
        end
        return [[input, option[:arch], source_name]] if raw_bpf_file?

        command = option[:command] || option[:ifile]
        dump_filters(command:, pid: nil, source: command)
      end

      # Was no filter source given on the command line?
      # @return [Boolean]
      def no_input?
        option[:command].nil? && option[:ifile].nil?
      end

      # Should the input be read directly as a raw BPF blob, rather than run as a command? True when
      # no +-c+ was given and the positional argument is not an executable (a plain file or stdin).
      # @return [Boolean]
      def raw_bpf_file?
        option[:command].nil? && !executable?
      end

      # Dumps filters from a command or pid and labels each with +source+.
      # @return [Array<Array(String, Symbol, String?)>]
      #   The filter tuples, empty when dumping is unsupported or nothing was installed.
      def dump_filters(command:, pid:, source:)
        return [] unless dumping_supported?

        filters = dump_seccomp(command:, pid:, limit: option[:limit], timeout: option[:timeout]) do |bpf, arch|
          [bpf, arch || option[:arch], source]
        end
        Logger.warn('No seccomp filter was installed.') if filters.empty?
        filters
      end

      # Is the positional input an ELF executable (rather than a raw BPF blob)?
      # @return [Boolean]
      def executable?
        return false if option[:ifile].nil? || option[:ifile] == '-'

        Util.elf?(option[:ifile])
      end

      # The label shown in the policy header; +<STDIN>+ when reading from stdin.
      # @return [String]
      def source_name
        option[:ifile] == '-' ? '<STDIN>' : option[:ifile]
      end
    end
  end
end
