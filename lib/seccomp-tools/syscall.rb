module SeccompTools
  # Record syscall number, arguments.
  class Syscall
    # TODO: move to const.rb
    PR_SET_SECCOMP = 22.freeze
    SECCOMP_MODE_FILTER = 2.freeze
    # TODO: how to build this table efficiently?
    ABI = {
      'x86_64' => {number: 120, args: [112, 104, 96, 56, 72, 44], SYS_prctl: 157}
    }.freeze

    attr_reader :abi, :number, :args
    def initialize(arch)
      raise ArgumentError unless block_given?
      raise ArgumentError("Only supports #{ABI.keys.join(', ')}") if ABI[arch].nil?
      @arch = arch
      @abi = ABI[arch]
      @number = yield(abi[:number])
      @args = abi[:args].map { |off| yield(off) }
    end

    def set_seccomp?
      number == abi[:SYS_prctl] && args[0] == PR_SET_SECCOMP && args[1] == SECCOMP_MODE_FILTER
    end
  end
end
