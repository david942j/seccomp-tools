# frozen_string_literal: true

require 'os'
require 'timeout'

require 'seccomp-tools/logger'
require 'seccomp-tools/ptrace' if OS.linux?
require 'seccomp-tools/syscall'

module SeccompTools
  # Dump seccomp-bpf using ptrace of binary.
  module Dumper
    # Whether the dumper is supported.
    # Dumper works based on ptrace, so we need the platform to be Linux.
    SUPPORTED = OS.linux?

    module_function

    # Main bpf dump function.
    # Yields seccomp bpf whenever a +prctl(SET_SECCOMP)+ call is found.
    #
    # @param [Array<String>] args
    #   The command to be executed, i.e. the target execution file followed by its arguments.
    # @param [Integer] limit
    #   By default, +dump+ will only dump the first +SET_SECCOMP+ call.
    #   Set +limit+ to the number of calling +prctl(SET_SECCOMP)+ then the child process will be killed when number of
    #   calling +prctl+ reaches +limit+.
    #
    #   Negative number for unlimited.
    # @param [Float?] timeout
    #   Number of seconds to wait for the target process. When the timeout is reached, the target
    #   process is killed and the filters dumped so far are returned. +nil+ for no timeout.
    # @yieldparam [String] bpf
    #   Seccomp bpf in raw bytes.
    # @yieldparam [Symbol?] arch
    #   Architecture of the target process, always +nil+ right now.
    # @return [Array<Object>, Array<String>]
    #   One entry per dumped filter: the block's return values when a block is given, otherwise the
    #   raw bytes. Empty on a non-Linux platform, where dumping is unsupported.
    # @example
    #   dump('ls', '-l', '-a')
    #   #=> []
    #   dump('spec/binary/twctf-2016-diary') { |c| c[0, 10] }
    #   #=> [" \x00\x00\x00\x00\x00\x00\x00\x15\x00"]
    def dump(*args, limit: 1, timeout: nil, &block)
      return [] unless SUPPORTED

      pid = fork { handle_child(*args) }
      Handler.new(pid).handle(limit, timeout: timeout, &block)
    end

    # Traces a forked child, single-stepping it through its syscalls and capturing the seccomp
    # filters it installs.
    class Handler
      # Instantiate a {Handler} object.
      # @param [Integer] pid
      #   The process id after fork.
      def initialize(pid)
        @pids = [pid]
        Process.waitpid(pid)
        opt = Ptrace::O_TRACESYSGOOD | Ptrace::O_TRACECLONE | Ptrace::O_TRACEFORK | Ptrace::O_TRACEVFORK
        Ptrace.setoptions(pid, 0, opt)
        Ptrace.syscall(pid, 0, 0)
      end

      # Tracer.
      #
      # @param [Integer] limit
      #   Child will be killed when number of calling +prctl(SET_SECCOMP)+ reaches +limit+.
      # @param [Float?] timeout
      #   Kill the child processes when +timeout+ seconds have elapsed. +nil+ for no timeout.
      # @yieldparam [String] bpf
      #   Seccomp bpf in raw bytes.
      # @yieldparam [Symbol] arch
      #   Architecture. See {SeccompTools::Syscall::ABI} for supported architectures.
      # @return [Array<Object>, Array<String>]
      #   One entry per dumped filter: the block's return values when a block is given, otherwise
      #   the raw bytes.
      def handle(limit, timeout: nil, &block)
        collect = []
        syscalls = {} # record last syscall
        begin
          Timeout.timeout(timeout) do
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
          end
        rescue Timeout::Error
          # keep the filters dumped so far; fall through to kill the children
        end
        @pids.each { |cpid| Process.kill('KILL', cpid) if alive?(cpid) }
        Process.waitall
        collect
      end

      private

      # Waits until a traced child enters or leaves a syscall, then resumes it.
      #
      # @yieldparam [Integer] pid
      #   Id of the child that stopped.
      # @yieldreturn [Boolean]
      #   Whether tracing should continue.
      # @return [Boolean]
      #   +true+ for continue,
      #   +false+ for break. Also +false+ once no children are left.
      def wait_syscall
        child, status = Process.wait2
        @pids << child unless @pids.include?(child)
        cont = true
        if [Ptrace::EVENT_CLONE, Ptrace::EVENT_FORK, Ptrace::EVENT_VFORK].include?(status.to_i >> 16)
          # New child launched!
          # newpid = SeccompTools::Ptrace.geteventmsg(child)
        elsif status.stopped? && status.stopsig & 0x80 != 0
          cont = yield(child)
        end
        Ptrace.syscall(child, 0, 0) unless status.exited?
        cont
      rescue Errno::ECHILD
        false
      end

      # Reads the syscall the stopped child is currently invoking.
      #
      # @param [Integer] pid
      #   Id of the stopped child.
      # @return [SeccompTools::Syscall]
      def syscall(pid)
        SeccompTools::Syscall.new(pid)
      end

      # Is the process still running?
      #
      # @param [Integer] pid
      #   Id of the process to be checked.
      # @return [Boolean]
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
      rescue # rubocop:disable Style/RescueStandardError
        Logger.error("Failed to execute #{args.join(' ')}")
        exit(1)
      end
    end

    # Dump installed seccomp-bpf of an existing process using PTRACE_SECCOMP_GET_FILTER.
    #
    # Dump the installed seccomp-bpf from a running process. This is achieved by the ptrace command
    # PTRACE_SECCOMP_GET_FILTER, which needs CAP_SYS_ADMIN capability.
    #
    # @param [Integer] pid
    #   Target process identifier.
    # @param [Integer] limit
    #   Number of filters to dump. Negative number for unlimited.
    # @yieldparam [String] bpf
    #   Seccomp bpf in raw bytes.
    # @yieldparam [Symbol] arch
    #   Architecture of the target process (always nil right now).
    # @return [Array<Object>, Array<String>]
    #   Returns what the block returned. If a block is not given, an array of raw bytes will be returned.
    # @raise [Errno::ESRCH]
    #   Raises when the target process does not exist.
    # @raise [Errno::EPERM]
    #   Raises the error if not allowed to attach.
    # @raise [Errno::EACCES]
    #   Raises the error if not allowed to dump (e.g. no CAP_SYS_ADMIN).
    # @example
    #   pid1 = Process.spawn('sleep inf')
    #   dump_by_pid(pid1, 1)
    #   # empty because there is no seccomp installed
    #   #=> []
    # @example
    #   pid2 = Process.spawn('spec/binary/twctf-2016-diary')
    #   # give it some time to install the filter
    #   sleep(1)
    #   dump_by_pid(pid2, 1) { |c| c[0, 10] }
    #   #=> [" \x00\x00\x00\x00\x00\x00\x00\x15\x00"]
    def dump_by_pid(pid, limit, &block)
      return [] unless SUPPORTED

      collect = []
      Ptrace.attach_and_wait(pid)
      begin
        i = 0
        while limit.negative? || i < limit
          begin
            bpf = Ptrace.seccomp_get_filter(pid, i)
          rescue Errno::ENOENT, Errno::EINVAL
            break
          end
          collect << (block.nil? ? bpf : yield(bpf, nil))
          i += 1
        end
      ensure
        Ptrace.detach(pid)
      end
      collect
    end
  end
end
