# frozen_string_literal: true

require 'shellwords'

require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/dumper'
require 'seccomp-tools/logger'

module SeccompTools
  module CLI
    # Handle 'dump' command.
    class Dump < Base
      # Summary of this command.
      SUMMARY = 'Automatically dump seccomp bpf from execution file(s).'
      # Usage of this command.
      USAGE = "dump - #{SUMMARY}\nNOTE : This function is only available on Linux." \
              "\n\nUsage: seccomp-tools dump [EXEC] [options]".freeze

      # Instantiate a {Dump} object, dumping the first filter as disassembly by default.
      #
      # Takes the same arguments as {Base#initialize}.
      def initialize(*)
        super
        option[:format] = :disasm
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
          opt.on('-c', '--sh-exec <command>', 'Executes the given command (via sh).',
                 'Use this option if want to pass arguments or do pipe things to the execution file.',
                 'e.g. use `-c "./bin > /dev/null"` to dump seccomp without being mixed with stdout.',
                 'Takes precedence over the [EXEC] argument.') do |command|
            option[:command] = command
          end

          opt.on('-f', '--format FORMAT', %i[disasm raw inspect],
                 'Output format. FORMAT can only be one of <disasm|raw|inspect>.',
                 'Default: disasm') do |f|
                   option[:format] = f
                 end

          opt.on('-l', '--limit LIMIT', 'Limit the number of calling "prctl(PR_SET_SECCOMP)".',
                 'The target process will be killed whenever its calling times reaches LIMIT.',
                 'Default: 1', Integer) do |l|
                   option[:limit] = l
                 end

          opt.on('-o', '--output FILE', 'Output result into FILE instead of stdout.',
                 'If multiple seccomp syscalls have been invoked (see --limit),',
                 'results will be written to FILE, FILE_1, FILE_2.. etc.',
                 'For example, "--output out.bpf" and the output files are out.bpf, out_1.bpf, ...') do |o|
                   option[:ofile] = o
                 end

          opt.on('-p', '--pid PID', 'Dump installed seccomp filters of the existing process.',
                 'You must have CAP_SYS_ADMIN (e.g. be root) in order to use this option.',
                 Integer) do |p|
            option[:pid] = p
          end

          opt.on('-t', '--timeout SEC', 'Timeout for the execution, in seconds.',
                 'The target process will be killed when the timeout expires.',
                 'This option is ignored when --pid is given.',
                 'Default: no timeout', Float) do |t|
                   option[:timeout] = t
                 end
        end
      end

      # Traces the target process and writes out the seccomp filters it installs.
      #
      # Only available on Linux, logs an error and returns otherwise.
      # @return [void]
      def handle
        return Logger.error('Dump is only available on Linux.') unless Dumper::SUPPORTED
        return unless super

        block = lambda do |bpf, arch|
          case option[:format]
          when :inspect then output { "\"#{bpf.bytes.map { |b| format('\\x%02X', b) }.join}\"\n" }
          when :raw then output { bpf }
          when :disasm then output { SeccompTools::Disasm.disasm(bpf, arch:) }
          end
        end
        # -c/--sh-exec takes precedence; a positional exec is used only when -c is absent.
        option[:command] ||= argv.shift unless option[:pid]
        warn_ignored_arguments
        if option[:pid].nil?
          SeccompTools::Dumper.dump('/bin/sh', '-c', option[:command], limit: option[:limit],
                                                                       timeout: option[:timeout], &block)
        else
          begin
            SeccompTools::Dumper.dump_by_pid(option[:pid], option[:limit], &block)
          rescue Errno::EPERM, Errno::EACCES => e
            Logger.error(<<~EOS)
            #{e}
            PTRACE_SECCOMP_GET_FILTER requires CAP_SYS_ADMIN
            Try:
                sudo env "PATH=$PATH" #{(%w[seccomp-tools] + ARGV).shelljoin}
            EOS
            exit(1)
          end
        end
      end

      private

      # Warns about positional arguments that are left unused, e.g. an [EXEC] given together with
      # +-c+, or anything after +--pid+. Dumping still proceeds.
      # @return [void]
      def warn_ignored_arguments
        return if argv.empty?

        Logger.warn("ignoring unused argument#{'s' if argv.size > 1}: #{argv.join(' ')}")
      end
    end
  end
end
