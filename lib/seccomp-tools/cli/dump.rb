require 'shellwords'

require 'seccomp-tools/cli/base'
require 'seccomp-tools/dumper'

module SeccompTools
  module CLI
    # Handle 'dump' command.
    class Dump < Base
      SUMMARY = 'Automatically dump seccomp bpf from execution file.'.freeze
      USAGE = ('dump - ' + SUMMARY + "\n\n" + 'Usage: seccomp-tools dump [exec] [options]').freeze

      def initialize(argv)
        super
        option[:format] = :disasm
        option[:limit] = 1
      end

      def usage
        USAGE
      end

      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-e', '--exec <command>', 'Executes the given command.',
                 'Use this option if want to pass arguments to the execution file.') do |command|
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
        end
      end

      def handle
        return unless super
        option[:command] = argv.shift unless argv.empty?
        SeccompTools::Dumper.dump(*Shellwords.split(option[:command]), limit: option[:limit]) do |bpf|
          case option[:format]
          when :inspect then output('"' + bpf.bytes.map { |b| format('\\x%02X', b) }.join + "\"\n")
          when :raw then output(bpf)
          when :disasm then nil # TODO: output(SeccompTools::Disasm.disasm(bpf))
          end
        end
      end

      private

      # Write data to stdout or file(s).
      def output(data)
        # if file name not present, just output to stdout.
        return $stdout.write(data) if option[:ofile].nil?
        # times of calling output
        @serial ||= 0
        IO.binwrite(file_of(option[:ofile], @serial), data)
        @serial += 1
      end

      def file_of(file, serial)
        suffix = serial.zero? ? '' : "_#{serial}"
        ext = File.extname(file)
        base = File.basename(file, ext)
        File.join(File.dirname(file), base + suffix) + ext
      end
    end
  end
end
