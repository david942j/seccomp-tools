require 'seccomp-tools/const'

module SeccompTools
  # For emulation seccomp.
  class Emulator
    # Instantiate a {Emulator} object.
    #
    # All parameters except +instructions+ are optional, while a warning will be shown if unset data being accessed.
    # @param [Array<Instruction::Base>] instructions
    # @param [Integer] sys_nr
    #   Syscall number.
    # @param [Array<Integer>] args
    #   Syscall arguments
    # @param [Integer] instruction_pointer
    #   Program counter address when this syscall invoked.
    # @param [Symbol] arch
    #   If not given, use system architecture as default.
    #
    #   See {SeccompTools::Util.supported_archs} for list of supported architectures.
    def initialize(instructions, sys_nr: nil, args: [], instruction_pointer: nil, arch: nil)
      @instructions = instructions
      @sys_nr = sys_nr
      @args = args
      @ip = instruction_pointer
      @arch = audit(arch || Util.system_arch)
    end

    # Run emulation!
    def run
      @values = { pc: 0 }
      loop do
        break if pc.nil? # returned or error occured
        inst = @instructions[pc]
        op, *args = inst.symbolize
        case op
        when :ret then ret(args.first) # ret
        when :ld then ld(args[0], args[1]) # ld/ldx
        when :st then st(args[0], args[1]) # st/stx
        when :jmp then jmp(args[0]) # directly jmp
        when :cmp then cmp(*args[0, 4]) # jmp with comparsion
        when :alu then alu(args[0], args[1]) # alu
        when :misc then misc(args[0]) # misc: txa/tax
        end
        set(:pc, get(:pc) + 1) if %i[ld st alu misc].include?(op)
      end
      p @values
    end

    def audit(arch)
      type = case arch
             when :amd64 then 'ARCH_X86_64'
             when :i386 then 'ARCH_I386'
             end
      Const::Audit::ARCH[type]
    end

    def pc
      @values[:pc]
    end

    private

    def ret(num)
      set(:pc, nil)
      set(:ret, num == :a ? get(:a) : num)
    end

    # @param [:a, :x] dst
    # @param [{rel: <:mem, :immi, :data>, val: Integer}] src
    def ld(dst, src)
      val = case src[:rel]
            when :immi then src[:val]
            when :mem then get(:mem, src[:val])
            when :data then get(:data, src[:val])
            end
      set(dst, val)
    end

    def set(*arg, val)
      if arg.size == 1
        arg = arg.first
        raise ArgumentError, "Invalid #{arg}" unless %i[a x pc ret].include?(arg)
        @values[arg] = val
      elsif arg.first == :mem # TODO: handle RangeError
        @values[arg[1]] = val
      else
        # Access data
        raise ArgumentError, arg.to_s
      end
    end

    def get(*arg)
      if arg.size == 1
        arg = arg.first
        raise ArgumentError, "Invalid #{arg}" unless %i[a x pc ret].include?(arg)
        return @values[arg]
      end
      return @values[arg[1]] if arg.first == :mem
      raise ArgumentError, arg.to_s
    end
  end
end
