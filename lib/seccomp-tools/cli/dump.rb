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
              "\n\nUsage: seccomp-tools dump [exec] [options]"

      def initialize(*)
        super
        option[:format] = :disasm
        option[:limit] = 1
        option[:pid] = nil
      end

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-c', '--sh-exec <command>', 'Executes the given command (via sh).',
                 'Use this option if want to pass arguments or do pipe things to the execution file.',
                 'e.g. use `-c "./bin > /dev/null"` to dump seccomp without being mixed with stdout.') do |command|
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
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return Logger.error('Dump is only available on Linux.') unless Dumper::SUPPORTED
        return unless super

        block = lambda do |bpf, arch|
          case option[:format]
          when :inspect then output { "\"#{bpf.bytes.map { |b| format('\\x%02X', b) }.join}\"\n" }
          when :raw then output { bpf }
          when :disasm then output { SeccompTools::Disasm.disasm(bpf, arch: arch) }
          end
        end
        if option[:pid].nil?
          option[:command] = argv.shift unless argv.empty?
          SeccompTools::Dumper.dump('/bin/sh', '-c', option[:command], limit: option[:limit], &block)
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
    end
  end
end
