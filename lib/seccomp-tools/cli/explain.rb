# frozen_string_literal: true

require 'shellwords'

require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/dumper'
require 'seccomp-tools/explain'
require 'seccomp-tools/logger'
require 'seccomp-tools/util'

module SeccompTools
  module CLI
    # Handle 'explain' command.
    class Explain < Base
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

          option_arch(opt)

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
        return if filters.nil?

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

      # Resolves the input into an array of +[raw_bpf, arch, source]+ tuples, or +nil+ when there is
      # nothing to do (help shown, or an error was logged).
      # @return [Array<Array(String, Symbol, String?)>, nil]
      def collect_filters
        return dump_pid if option[:pid]

        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:command].nil? && option[:ifile].nil?

        option[:command] || executable? ? dump_exec : [[input, option[:arch], source_name]]
      end

      # Dumps the filters installed by running an executable.
      def dump_exec
        return unsupported unless SeccompTools::Dumper::SUPPORTED

        command = option[:command] || option[:ifile]
        filters = SeccompTools::Dumper.dump('/bin/sh', '-c', command, limit: option[:limit],
                                                                      timeout: option[:timeout]) do |bpf, arch|
          [bpf, arch || option[:arch], command]
        end
        filters.empty? ? none_installed : filters
      end

      # Dumps the filters installed on an existing process.
      def dump_pid
        return unsupported unless SeccompTools::Dumper::SUPPORTED

        filters = SeccompTools::Dumper.dump_by_pid(option[:pid], option[:limit]) do |bpf, arch|
          [bpf, arch || option[:arch], "pid #{option[:pid]}"]
        end
        filters.empty? ? none_installed : filters
      rescue Errno::EPERM, Errno::EACCES => e
        Logger.error(<<~EOS)
          #{e}
          PTRACE_SECCOMP_GET_FILTER requires CAP_SYS_ADMIN
          Try:
              sudo env "PATH=$PATH" #{(%w[seccomp-tools] + ARGV).shelljoin}
        EOS
        exit(1)
      end

      # Logs that nothing was installed and returns +nil+ so {#handle} prints nothing.
      # @return [nil]
      def none_installed
        Logger.warn('No seccomp filter was installed.')
        nil
      end

      # Is the positional input an ELF executable (rather than a raw BPF blob)?
      # @return [Boolean]
      def executable?
        return false if option[:ifile].nil? || option[:ifile] == '-'

        Util.elf?(option[:ifile])
      end

      # The label shown in the policy header, +nil+ when reading from stdin.
      # @return [String?]
      def source_name
        option[:ifile] == '-' ? nil : option[:ifile]
      end

      def unsupported
        Logger.error('Dumping a filter from an executable or process is only available on Linux.')
        nil
      end
    end
  end
end
