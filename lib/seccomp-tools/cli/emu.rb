require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/emulator'

module SeccompTools
  module CLI
    # Handle 'emu' command.
    class Emu < Base
      # Summary of this command.
      SUMMARY = 'Emulate seccomp rules.'.freeze
      # Usage of this command.
      USAGE = ('emu - ' +
               SUMMARY +
               "\n\n" \
               'Usage: seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 [arg1 ... arg5]]]').freeze

      def initialize(*)
        super
        option[:verbose] = 0
      end

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage

          supported = Util.supported_archs
          opt.on('-a', '--arch ARCH', supported, 'Specify architecture.',
                 "Supported architectures are <#{supported.join('|')}>.") do |a|
            option[:arch] = a
          end

          opt.on('-q', '--[no-]quiet', 'Run quietly, only show emulation result.') do |v|
            option[:verbose] = 0 if v
          end

          opt.on('-v', 'Run verbosely.') do |_|
            option[:verbose] += 1
          end
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return unless super
        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:ifile].nil?
        raw = IO.binread(option[:ifile])
        insts = SeccompTools::Disasm.to_bpf(raw, option[:arch]).map(&:inst)
        sys, *args = argv
        sys = Integer(sys) if sys
        args.map! { |v| Integer(v) }
        p SeccompTools::Emulator.new(insts, sys_nr: sys, args: args, arch: option[:arch]).run
      end
    end
  end
end
