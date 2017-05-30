require 'seccomp-tools/const'

module SeccompTools
  # Record syscall number, arguments.
  class Syscall
    # TODO: how to build this table efficiently?
    #
    # Offsets of +struct user+ in different arch.
    ABI = {
      'amd64' => { number: 120, args: [112, 104, 96, 56, 72, 44], SYS_prctl: 157 }
    }.freeze

    attr_reader :abi, :number, :args
    def initialize(arch)
      raise ArgumentError, 'Block must be given' unless block_given?
      raise ArgumentError, "Only supports #{ABI.keys.join(', ')}" if ABI[arch].nil?
      @arch = arch
      @abi = ABI[arch]
      @number = yield(abi[:number])
      @args = abi[:args].map { |off| yield(off) }
    end

    # Is this a +prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, addr)+ syscall?
    def set_seccomp?
      # TODO: handle SECCOMP_MODE_STRICT
      number == abi[:SYS_prctl] && args[0] == Const::BPF::PR_SET_SECCOMP && args[1] == Const::BPF::SECCOMP_MODE_FILTER
    end
  end
end
