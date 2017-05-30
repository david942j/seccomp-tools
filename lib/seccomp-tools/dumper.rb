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
    #   Negative number or zero for unlimited.
    # @yieldparam [String] bpf
    #   Seccomp bpf in raw bytes.
    # @return [Array<Object>, Array<String>]
    #   Return the block returned. If block is not given, array of raw bytes will be returned.
    # @example
    #   dump('ls', '-l', '-a')
    #   #=> []
    #   dump('spec/binary/twctf-2016-diary') { |c| c[0, 10] }
    #   #=> [" \x00\x00\x00\x00\x00\x00\x00\x15\x00"]
    # @todo
    #   Detect execution file architecture to know which syscall number should be traced.
    # @todo
    #   +timeout+ option.
    def dump(*args, limit: 1, &block)
      pid = fork { handle_child(*args) }
      Handler.new(pid).handle(limit, &block)
    end

    # Do the tracer things.
    class Handler
      def initialize(pid)
        @pid = pid
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
        Process.waitpid(@pid)
        SeccompTools::Ptrace.setoptions(@pid, 0, 1 | 2 | 4 | 8) # TODO: PTRACE_O_TRACESYSGOOD ..
        SeccompTools::Ptrace.syscall(@pid, 0, 0)
        collect = []
        status = {}
        loop while wait_syscall do |child|
          if status[child].nil? # invoke syscall
            status[child] = syscall(child)
            next true
          end
          # syscall finished
          sys = status[child]
          status[child] = nil
          # TODO: maybe the prctl(SET_SECCOMP) call failed?
          if sys.set_seccomp?
            bpf = dump_bpf(child, sys.args[2])
            collect << (block.nil? ? bpf : yield(bpf))
            limit -= 1
            next false if limit.zero?
          end
          true
        end
        status.keys.each { |cpid| Process.kill('KILL', cpid) if alive?(cpid) }
        collect
      end

      private

      # @return [Boolean]
      #   Return +false+ if and only if child exited.
      def wait_syscall
        child, status = Process.wait2
        cont = true
        if status >> 16 == 1 # PTRACE_EVENT_FORK
          newpid = SeccompTools::Ptrace.geteventmsg(child)
          Process.waitpid(newpid)
          SeccompTools::Ptrace.syscall(newpid, 0, 0)
        elsif status.stopped? && status.stopsig & 0x80 != 0
          cont = yield(child)
        end
        SeccompTools::Ptrace.syscall(child, 0, 0) unless status.exited?
        return cont
      rescue Errno::ECHILD
        return false
      end

      # @return [SeccompTools::Syscall]
      def syscall(pid)
        SeccompTools::Syscall.new('amd64') do |offset|
          Ptrace.peekuser(pid, offset, 0)
        end
      end

      # Dump bpf from addr.
      def dump_bpf(pid, addr)
        len = Ptrace.peekdata(pid, addr, 0) & 0xffff # len is unsigned short
        # TODO: Use __buildin_offset instead of hardcode
        filter = Ptrace.peekdata(pid, addr + 8, 0)
        Array.new(len) { |i| Ptrace.peekdata(pid, filter + i * 8, 0) }.pack('Q*')
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
        SeccompTools::Ptrace.traceme_and_stop
        exec(*args)
      rescue # exec fail
        exit(1)
      end
    end
  end
end
