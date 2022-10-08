# frozen_string_literal: true

require 'seccomp-tools/cli/base'
require 'seccomp-tools/asm/asm'

module SeccompTools
  module CLI
    # Handle 'asm' command.
    class Asm < Base
      # Summary of this command.
      SUMMARY = 'Seccomp bpf assembler.'
      # Usage of this command.
      USAGE = "asm - #{SUMMARY}\n\nUsage: seccomp-tools asm IN_FILE [options]"

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

          opt.on('-f', '--format FORMAT', %i[inspect raw c_array carray c_source assembly],
                 'Output format. FORMAT can only be one of <inspect|raw|c_array|c_source|assembly>.',
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

        res = SeccompTools::Asm.asm(input, filename: option[:ifile], arch: option[:arch])
        output do
          case option[:format]
          when :inspect then "#{res.inspect}\n"
          when :raw then res
          when :c_array, :carray then "unsigned char bpf[] = {#{res.bytes.join(',')}};\n"
          when :c_source then SeccompTools::Util.template('asm.c').sub('<TO_BE_REPLACED>', res.bytes.join(','))
          when :assembly
            SeccompTools::Util.template("asm.#{option[:arch]}.asm").sub(
              '<TO_BE_REPLACED>',
              res.bytes.map { |b| format('\\\%03o', b) }.join
            )
          end
        end
      end
    end
  end
end
