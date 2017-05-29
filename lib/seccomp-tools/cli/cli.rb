require 'seccomp-tools/cli/dump'
require 'seccomp-tools/version'

module SeccompTools
  # Handle CLI arguments parse.
  module CLI
    # Handled commands
    COMMANDS = {
      'dump' => SeccompTools::CLI::Dump
    }.freeze

    # Main usage message.
    USAGE = <<EOS.sub('%COMMANDS', COMMANDS.map { |k, v| "\t#{k}\t#{v::SUMMARY}" }.join("\n")).freeze
Usage: seccomp-tools [--version] [--help] <command> [<options>]

These are list of commands:
%COMMANDS

See 'seccomp-tools help <command>' or 'seccomp-tools <command> -h' to read about a specific subcommand.
EOS

    module_function

    # Main work method for CLI.
    # @param [Array<String>] argv
    #   Command line arguments.
    # @return [void]
    # @example
    #   work(argv: %w[--help])
    #   #=> # usage message
    #   work(argv: %w[--version])
    #   #=> # version message
    def work(argv)
      idx = argv.index { |c| !c.start_with?('-') }
      preoption = idx.nil? ? argv.shift(argv.size) : argv.shift(idx)

      # handle --version or --help or nothing
      return show("SeccompTools Version #{SeccompTools::VERSION}") if preoption.include?('--version')
      return show(USAGE) if preoption.include?('--help') || idx.nil?

      # let's handle commands
      cmd = argv.shift
      if cmd == 'help' # special case
        cmd = argv.shift
        argv = %w[--help]
      end
      return show(invalid(cmd)) if COMMANDS[cmd].nil?
      COMMANDS[cmd].new(argv).handle
    end

    def show(msg)
      puts msg
      false
    end

    def invalid(cmd)
      format("Invalid command '%s'\n\nSee 'seccomp-tools --help' for list of valid commands", cmd)
    end
  end
end
