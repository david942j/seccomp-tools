require 'seccomp-tools/cli/base'
require 'seccomp-tools/asm/asm'

module SeccompTools
  module CLI
    # Handle 'asm' command.
    class Asm < Base
      # Summary of this command.
      SUMMARY = 'Seccomp bpf assembler.'.freeze
      # Usage of this command.
      USAGE = ('asm - ' + SUMMARY + "\n\n" + 'Usage: seccomp-tools asm IN_FILE [options]').freeze

      def initialize(*)
        super
        option[:format] = :inspect
      end

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-o', '--output FILE', 'Output result into FILE instead of stdout.') do |o|
            option[:ofile] = o
          end

          opt.on('-f', '--format FORMAT', %i[inspect raw carray],
                 'Output format. FORMAT can only be one of <inspect|raw|carray>.',
                 'Default: inspect') do |f|
                   option[:format] = f
                 end

          option_arch(opt)
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return unless super
        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:ifile].nil?
        res = SeccompTools::Asm.asm(input, arch: option[:arch])
        output do
          case option[:format]
          when :inspect then res.inspect + "\n"
          when :raw then res
          when :carray then "unsigned char bpf[] = {#{res.bytes.join(',')}};\n"
          end
        end
      end
    end
  end
end
