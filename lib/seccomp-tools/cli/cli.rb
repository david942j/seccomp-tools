# frozen_string_literal: true

require 'seccomp-tools/cli/asm'
require 'seccomp-tools/cli/disasm'
require 'seccomp-tools/cli/dump'
require 'seccomp-tools/cli/emu'
require 'seccomp-tools/version'

module SeccompTools
  # Handle CLI arguments parse.
  module CLI
    # Handled commands
    COMMANDS = {
      'asm' => SeccompTools::CLI::Asm,
      'disasm' => SeccompTools::CLI::Disasm,
      'dump' => SeccompTools::CLI::Dump,
      'emu' => SeccompTools::CLI::Emu
    }.freeze

    # Main usage message.
    USAGE = <<EOS.sub('%COMMANDS', COMMANDS.map { |k, v| "\t#{k}\t#{v::SUMMARY}" }.join("\n")).freeze
Usage: seccomp-tools [--version] [--help] <command> [<options>]

List of commands:

%COMMANDS

See 'seccomp-tools <command> --help' to read about a specific subcommand.
EOS

    module_function

    # Main working method of CLI.
    # @param [Array<String>] argv
    #   Command line arguments.
    # @return [void]
    # @example
    #   work(%w[--help])
    #   #=> # usage message
    #   work(%w[--version])
    #   #=> # version message
    def work(argv)
      # all -h equivalent to --help
      argv = argv.map { |a| a == '-h' ? '--help' : a }
      idx = argv.index { |c| !c.start_with?('-') }
      preoption = idx.nil? ? argv.shift(argv.size) : argv.shift(idx)

      # handle --version or --help or nothing
      return show("SeccompTools Version #{SeccompTools::VERSION}") if preoption.include?('--version')
      return show(USAGE) if idx.nil?

      # let's handle commands
      cmd = argv.shift
      argv = %w[--help] if preoption.include?('--help')
      return show(invalid(cmd)) if COMMANDS[cmd].nil?

      COMMANDS[cmd].new(argv).handle
    end

    # Just write message to stdout.
    # @param [String] msg
    #   The message.
    # @return [false]
    #   Always return +false+.
    def show(msg)
      puts msg
      false
    end

    class << self
      private

      # Invalid command message.
      def invalid(cmd)
        format("Invalid command '%s'\n\nSee 'seccomp-tools --help' for list of valid commands", cmd)
      end
    end
  end
end
