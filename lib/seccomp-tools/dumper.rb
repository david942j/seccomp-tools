require 'seccomp-tools/ptrace'
require 'seccomp-tools/syscall'

module SeccompTools
  # Dump seccomp-bpf using ptrace of binary.
  # Currently only support x86_64.
  module Dumper
    module_function

    # Main bpf dump function.
    # Yield seccomp bpf whenever find a +prctl(SET_SECCOMP)+ call.
    #
    # @param [Array<String>] args
    #   The arguments for target execution file.
    # @param [Integer] limit
    #   By default, +dump+ will only dump the first +SET_SECCOMP+ call.
    #   Set +limit+ to the number of calling +prctl(SET_SECCOMP)+ then the child process will be killed when number of
    #   calling +prctl+ reaches +limit+.
    #
    #   Negative number for unlimited.
    # @yieldparam [String] bpf
    #   Seccomp bpf in raw bytes.
    # @yieldparam [Symbol] arch
    #   Architecture of the target process.
    # @return [Array<Object>, Array<String>]
    #   Return the block returned. If block is not given, array of raw bytes will be returned.
    # @example
    #   dump('ls', '-l', '-a')
    #   #=> []
    #   dump('spec/binary/twctf-2016-diary') { |c| c[0, 10] }
    #   #=> [" \x00\x00\x00\x00\x00\x00\x00\x15\x00"]
    # @todo
    #   +timeout+ option.
    def dump(*args, limit: 1, &block)
      pid = fork { handle_child(*args) }
      Handler.new(pid).handle(limit, &block)
    end

    # Do the tracer things.
    class Handler
      # Instantiate a {Handler} object.
      # @param [Integer] pid
      #   The process id after fork.
      def initialize(pid)
        Process.waitpid(pid)
        opt = Ptrace::O_TRACESYSGOOD | Ptrace::O_TRACECLONE | Ptrace::O_TRACEFORK | Ptrace::O_TRACEVFORK
        Ptrace.setoptions(pid, 0, opt)
        Ptrace.syscall(pid, 0, 0)
      end

      # Tracer.
      #
      # @param [Integer] limit
      #   Child will be killed when number of calling +prctl(SET_SECCOMP)+ reaches +limit+.
      # @yieldparam [String] bpf
      #   Seccomp bpf in raw bytes.
      # @return [Array<Object>, Array<String>]
      #   Return the block returned. If block is not given, array of raw bytes will be returned.
      def handle(limit, &block)
        collect = []
        syscalls = {} # record last syscall
        loop while wait_syscall do |child|
          if syscalls[child].nil? # invoke syscall
            syscalls[child] = syscall(child)
            next true
          end
          # syscall finished
          sys = syscalls[child]
          syscalls[child] = nil
          if sys.set_seccomp? && syscall(child).ret.zero? # consider successful call only
            bpf = sys.dump_bpf
            collect << (block.nil? ? bpf : yield(bpf, sys.arch))
            limit -= 1
          end
          !limit.zero?
        end
        syscalls.keys.each { |cpid| Process.kill('KILL', cpid) if alive?(cpid) }
        collect
      end

      private

      # @yieldparam [Integer] pid
      # @return [Boolean]
      #   +true+ for continue,
      #   +false+ for break.
      def wait_syscall
        child, status = Process.wait2
        cont = true
        # TODO: Test if clone / vfork works
        if [Ptrace::EVENT_CLONE, Ptrace::EVENT_FORK, Ptrace::EVENT_VFORK].include?(status >> 16)
          # New child launched!
          # newpid = SeccompTools::Ptrace.geteventmsg(child)
        elsif status.stopped? && status.stopsig & 0x80 != 0
          cont = yield(child)
        end
        Ptrace.syscall(child, 0, 0) unless status.exited?
        return cont
      rescue Errno::ECHILD
        return false
      end

      # @return [SeccompTools::Syscall]
      def syscall(pid)
        SeccompTools::Syscall.new(pid)
      end

      def alive?(pid)
        Process.getpgid(pid)
        true
      rescue Errno::ESRCH
        false
      end
    end

    class << self
      private

      def handle_child(*args)
        Ptrace.traceme_and_stop
        exec(*args)
      rescue # exec fail
        # TODO: use logger
        $stderr.puts("Failed to execute #{args.join(' ')}")
        exit(1)
      end
    end
  end
end
