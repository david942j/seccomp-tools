require 'seccomp-tools/ptrace'
require 'seccomp-tools/syscall'

module SeccompTools
  # Dump seccomp-bpf using ptrace of binary.
  # Currently only support x86_64.
  module Dumper
    module_function

    # Main work function.
    # @param [Array<String>] args
    #   The arguments for target process.
    # @return [Array<String>]
    #   Array of bpf bytes.
    # @example
    #   dump('ls', '-l', '-a')
    #   #=> []
    #   dump('spec/binary/simple_case')
    #   #=> TODO
    # @todo
    #   Detect execution file architecture to know should trace which syscall number.
    def dump(*args, verbose: false)
      pid = fork { handle_child(*args) }
      handle_trace(pid)
    end

    class << self
      private

      def handle_child(*args)
        SeccompTools::Ptrace.traceme_and_stop
        exec(*args)
        exit(1) # exec fail
      end

      def handle_trace(pid)
        Process.waitpid(pid)
        SeccompTools::Ptrace.setoptions(pid, 0, 1) # TODO: PTRACE_O_TRACESYSGOOD
        loop do
          break unless wait_syscall(pid)
          sys = get_args(pid)
          break unless wait_syscall(pid)
          # TODO: maybe the prctl(SET_SECCOMP) call failed?
          record(sys) if sys.set_seccomp?
        end
        Process.kill('KILL', pid)
      end

      def wait_syscall(pid)
        loop do
          SeccompTools::Ptrace.syscall(pid, 0, 0)
          _, status = Process.waitpid2(pid)
          return true if status.stopped? && status.stopsig & 0x80 != 0
          return false if status.exited?
          # p 'wtf?', status
        end
      end

      # @return [SeccompTools::Syscall]
      def get_args(pid)
        SeccompTools::Syscall.new('x86_64') do |offset|
          Ptrace.peekuser(pid, offset, 0)
        end
      end

      def record(syscall)
        p syscall
      end
    end
  end
end
