# frozen_string_literal: true

require 'shellwords'

require 'seccomp-tools/dumper'
require 'seccomp-tools/logger'

module SeccompTools
  module CLI
    # Shared helpers for commands that dump seccomp filters via ptrace (currently {Dump}).
    module Dumpable
      # Dumps the seccomp filters from a command run via +sh+, or from an existing process, yielding
      # each installed filter.
      #
      # When +pid+ is given the process is traced (requiring +CAP_SYS_ADMIN+); otherwise +command+
      # is executed. On a permission error while tracing a pid, {#dump_permission_error} exits.
      # @param [String?] command
      #   The command to run, when +pid+ is +nil+.
      # @param [Integer?] pid
      #   The process to trace, or +nil+ to run +command+.
      # @param [Integer] limit
      #   Stop after this many installed filters.
      # @param [Float?] timeout
      #   Seconds to wait for +command+, ignored when tracing a pid.
      # @yieldparam [String] bpf
      #   One installed filter, as raw bytes.
      # @yieldparam [Symbol?] arch
      #   The architecture of the traced process, if known.
      # @return [Array]
      #   One entry per filter: the block's return values.
      def dump_seccomp(command:, pid:, limit:, timeout:, &)
        return dump_seccomp_by_pid(pid, limit, &) if pid

        SeccompTools::Dumper.dump('/bin/sh', '-c', command, limit:, timeout:, &)
      end

      # Whether tracer-based dumping is available on this platform (Linux only). Logs an error when
      # it is not, so callers can guard with +return unless dumping_supported?+.
      # @return [Boolean]
      def dumping_supported?
        return true if SeccompTools::Dumper::SUPPORTED

        Logger.error('Dumping a filter from an executable or process is only available on Linux.')
        false
      end

      private

      # Traces +pid+, translating a permission error into the standard hint.
      def dump_seccomp_by_pid(pid, limit, &)
        SeccompTools::Dumper.dump_by_pid(pid, limit, &)
      rescue Errno::EPERM, Errno::EACCES => e
        dump_permission_error(e)
      end

      # Reports a permission error from tracing a process and exits.
      #
      # Dumping a filter by pid needs +CAP_SYS_ADMIN+ for +PTRACE_SECCOMP_GET_FILTER+.
      # @param [SystemCallError] err
      #   The +Errno::EPERM+ or +Errno::EACCES+ that was raised.
      # @raise [SystemExit]
      #   Always; the process is terminated with exit status 1.
      def dump_permission_error(err)
        Logger.error(<<~EOS)
          #{err}
          PTRACE_SECCOMP_GET_FILTER requires CAP_SYS_ADMIN
          Try:
              sudo env "PATH=$PATH" #{(%w[seccomp-tools] + ARGV).shelljoin}
        EOS
        exit(1)
      end
    end
  end
end
