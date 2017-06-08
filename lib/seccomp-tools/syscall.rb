require 'seccomp-tools/const'
require 'seccomp-tools/ptrace'

module SeccompTools
  # Record syscall number, arguments, return value.
  class Syscall
    # Syscall arguments offset of +struct user+ in different arch.
    ABI = {
      amd64: { number: 120, args: [112, 104, 96, 56, 72, 44], ret: 80, SYS_prctl: 157 },
      i386: { number: 120, args: [40, 88, 96, 104, 112, 32], ret: 80, SYS_prctl: 172 }
    }.freeze

    # @return [Integer] Process id.
    attr_reader :pid
    # @return [Hash{Symbol => Integer, Array<Integer>}] See {ABI}.
    attr_reader :abi
    # @return [Integer] Syscall number.
    attr_reader :number
    # @return [Integer] Syscall arguments.
    attr_reader :args
    # @return [Integer] Syscall return value.
    attr_reader :ret

    # Instantiate a {Syscall} object.
    # @param [String] pid
    #   Process-id.
    def initialize(pid)
      @pid = pid
      raise ArgumentError, "Only supports #{ABI.keys.join(', ')}" if ABI[arch].nil?
      @abi = ABI[arch]
      @number = peek(abi[:number])
      @args = abi[:args].map { |off| peek(off) }
      @ret = peek(abi[:ret])
    end

    # Is this a +prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, addr)+ syscall?
    # @return [Boolean]
    #   +true+ for is a seccomp installation syscall.
    def set_seccomp?
      # TODO: handle SECCOMP_MODE_STRICT
      number == abi[:SYS_prctl] && args[0] == Const::BPF::PR_SET_SECCOMP && args[1] == Const::BPF::SECCOMP_MODE_FILTER
    end

    # Dump bpf byte from +args[2]+.
    # @return [String]
    def dump_bpf
      addr = args[2]
      len = Ptrace.peekdata(pid, addr, 0) & 0xffff # len is unsigned short
      filter = Ptrace.peekdata(pid, addr + bits / 8, 0) & ((1 << bits) - 1)
      Array.new(len) { |i| Ptrace.peekdata(pid, filter + i * 8, 0) }.pack('Q*')
    end

    # @return [Symbol]
    #   Architecture of this syscall.
    def arch
      @arch ||= File.open("/proc/#{pid}/exe", 'rb') do |f|
        f.pos = 4
        case f.read(1).ord
        when 1 then :i386
        when 2 then :amd64
        end
      end
    end

    private

    def bits
      case arch
      when :i386 then 32
      when :amd64 then 64
      end
    end

    def peek(offset)
      Ptrace.peekuser(pid, offset, 0)
    end
  end
end
