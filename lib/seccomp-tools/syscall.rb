# encoding: ascii-8bit
# frozen_string_literal: true

require 'os'

require 'seccomp-tools/const'
require 'seccomp-tools/ptrace' if OS.linux?

module SeccompTools
  # Record syscall number, arguments, return value.
  class Syscall
    # Syscall arguments offset of +struct user+ in different arch.
    ABI = {
      amd64: { number: 120, args: [112, 104, 96, 56, 72, 44], ret: 80, SYS_prctl: 157, SYS_seccomp: 317 },
      i386: { number: 44, args: [0, 4, 8, 12, 16, 20], ret: 24, SYS_prctl: 172, SYS_seccomp: 354 },
      aarch64: { number: 64, args: [0, 8, 16, 24, 32, 40, 48], ret: 0, SYS_prctl: 167, SYS_seccomp: 277 },
      riscv64: { number: 136, args: [80, 88, 96, 104, 112, 120], ret: 80, SYS_prctl: 167, SYS_seccomp: 277 },
      # Most software invokes syscalls through "svc 0", in which case the syscall number is in r1.
      # However, it's also possible to use "svc NR": this case is not handled here.
      s390x: { number: 24, args: [32, 40, 48, 56, 64, 72], ret: 32, SYS_prctl: 172, SYS_seccomp: 348 }
    }.freeze

    # @return [Integer] Id of the traced process.
    attr_reader :pid
    # @return [{Symbol => Integer, Array<Integer>}]
    #   The {ABI} entry of this syscall's architecture.
    attr_reader :abi
    # @return [Integer] Syscall number.
    attr_reader :number
    # @return [Array<Integer>] Syscall arguments, in register order.
    attr_reader :args
    # @return [Integer] Syscall return value.
    attr_reader :ret

    # Instantiate a {Syscall} object.
    #
    # Reads the syscall number, arguments and return value of +pid+ through ptrace, so the process
    # must already be stopped and attached.
    # @param [Integer] pid
    #   Id of the traced process.
    # @raise [ArgumentError]
    #   If the architecture of +pid+ is not one of {ABI}'s keys.
    def initialize(pid)
      @pid = pid
      raise ArgumentError, "Only supports #{ABI.keys.join(', ')}" if ABI[arch].nil?

      @abi = ABI[arch]
      @number = peek(abi[:number])
      @args = abi[:args].map { |off| peek(off) }
      @ret = peek(abi[:ret])
    end

    # Is this a seccomp installation syscall?
    #
    # Both +SECCOMP_MODE_FILTER+ and +SECCOMP_MODE_STRICT+ installations are recognized, invoked
    # through either +seccomp+ or +prctl(PR_SET_SECCOMP, ...)+.
    # @return [Boolean]
    #   +true+ if this is a seccomp installation syscall.
    def set_seccomp?
      filter_mode? || strict_mode?
    end

    # Is this a +seccomp(SECCOMP_SET_MODE_FILTER, ..)+/+prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ..)+ syscall?
    #
    # @return [Boolean]
    def filter_mode?
      return true if number == abi[:SYS_seccomp] && args[0] == Const::BPF::SECCOMP_SET_MODE_FILTER

      number == abi[:SYS_prctl] && args[0] == Const::BPF::PR_SET_SECCOMP && args[1] == Const::BPF::SECCOMP_MODE_FILTER
    end

    # Is this a +seccomp(SECCOMP_SET_MODE_STRICT, ..)+/+prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)+ syscall?
    #
    # @return [Boolean]
    def strict_mode?
      return true if number == abi[:SYS_seccomp] && args[0] == Const::BPF::SECCOMP_SET_MODE_STRICT

      number == abi[:SYS_prctl] && args[0] == Const::BPF::PR_SET_SECCOMP && args[1] == Const::BPF::SECCOMP_MODE_STRICT
    end

    # Constructs a BPF program equivalent to what +SECCOMP_MODE_STRICT+ enforces: only read, write,
    # exit, and sigreturn are allowed, while any other syscall kills the thread.
    #
    # @param [Symbol] arch
    #   Target architecture, one of {ABI}'s keys.
    # @return [String]
    #   Raw BPF bytes.
    def self.strict_bpf(arch)
      # Required lazily because the assembler's scanner refers to {ABI} at load time.
      require 'seccomp-tools/asm/asm'

      # The kernel checks sigreturn on architectures that have it and rt_sigreturn on the others.
      sigreturn = Const::Syscall.const_get(arch.to_s.upcase)[:sigreturn] ? :sigreturn : :rt_sigreturn
      Asm.asm(<<-EOS, arch: arch)
        A = sys_number
        A == read ? ok : next
        A == write ? ok : next
        A == exit ? ok : next
        A == #{sigreturn} ? ok : next
        return KILL
        ok:
        return ALLOW
      EOS
    end

    # Dumps the BPF of the filter being installed.
    #
    # Only meaningful when {#set_seccomp?} is +true+. In filter mode +args[2]+ points to a
    # +struct sock_fprog+ in the traced process, whose BPF bytes are read out. Strict mode installs
    # no BPF, so an equivalent filter built by {.strict_bpf} is returned instead.
    # @return [String]
    #   The raw BPF bytes of the filter being installed.
    def dump_bpf
      return self.class.strict_bpf(arch) if strict_mode?

      addr = args[2]
      len = Ptrace.peekdata(pid, addr, 0) & 0xffff # len is unsigned short
      filter = Ptrace.peekdata(pid, addr + (bits / 8), 0) & ((1 << bits) - 1)
      Array.new(len) { |i| Ptrace.peekdata(pid, filter + (i * 8), 0) }.pack('Q*')
    end

    # Architecture of this syscall, determined by the ELF machine type of +/proc/pid/exe+.
    # @return [Symbol?]
    #   One of +:i386+, +:amd64+, +:aarch64+, +:riscv64+, +:s390x+, or +nil+ if the machine type is
    #   unrecognized.
    def arch
      @arch ||= File.open("/proc/#{pid}/exe", 'rb') do |f|
        f.pos = 18
        {
          "\x03\x00" => :i386,
          "\x3e\x00" => :amd64,
          "\xb7\x00" => :aarch64,
          "\xf3\x00" => :riscv64,
          "\x00\x16" => :s390x
        }[f.read(2)]
      end
    end

    private

    def bits
      {
        i386: 32,
        amd64: 64,
        aarch64: 64,
        riscv64: 64,
        s390x: 64
      }[arch]
    end

    def peek(offset)
      Ptrace.peekuser(pid, offset, 0, bits)
    end
  end
end
