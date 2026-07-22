# frozen_string_literal: true

require 'seccomp-tools/const'

module SeccompTools
  # Runs a seccomp filter against a hypothetical syscall to find out which action it returns.
  class Emulator
    # Instantiate a {Emulator} object.
    #
    # All parameters except +instructions+ are optional. A warning is shown when uninitialized data is accessed.
    # @param [Array<Instruction::Base>] instructions
    #   The filter to be emulated, as returned by +SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)+.
    # @param [Integer?] sys_nr
    #   Syscall number.
    # @param [Array<Integer>] args
    #   Syscall arguments
    # @param [Integer?] instruction_pointer
    #   Program counter address when this syscall is invoked.
    # @param [Symbol?] arch
    #   Defaults to the system architecture when not provided.
    #
    #   See {SeccompTools::Util.supported_archs} for list of supported architectures.
    def initialize(instructions, sys_nr: nil, args: [], instruction_pointer: nil, arch: nil)
      @instructions = instructions
      @sys_nr = sys_nr
      @args = args
      @ip = instruction_pointer
      arch ||= Util.system_arch
      @arch = audit(arch)
      # On a big-endian architecture the high 32-bit word of a 64-bit field comes first.
      @big_endian = Const::Endian.big?(arch)
    end

    # Run emulation!
    #
    # Executes the filter until it returns, then reports the final machine state.
    # @yieldparam [{Symbol, Integer => Integer}] values
    #   If a block is given, it is invoked before each instruction with the current machine state.
    # @return [{Symbol, Integer => Integer}]
    #   The final state: +:ret+ is the action the filter returned, +:pc+ the line it returned from,
    #   +:a+ and +:x+ the registers, and Integer keys the scratch memory slots.
    # @example
    #   insts = SeccompTools::Disasm.to_bpf(raw, :amd64).map(&:inst)
    #   SeccompTools::Emulator.new(insts, sys_nr: 0).run[:ret]
    #   #=> 2147418112 # SECCOMP_RET_ALLOW
    def run
      @values = { pc: 0, a: 0, x: 0 }
      loop do
        break if @values[:ret] # break when returned

        yield(@values) if block_given?
        inst = @instructions[pc]
        op, *args = inst.symbolize
        case op
        when :ret then ret(args.first) # ret
        when :ld then ld(args[0], args[1]) # ld/ldx
        when :st then st(args[0], args[1]) # st/stx
        when :jmp then jmp(args[0]) # directly jmp
        when :cmp then cmp(*args[0, 4]) # jmp with comparison
        when :alu then alu(args[0], args[1]) # alu
        when :misc then misc(args[0]) # misc: txa/tax
        end
        set(:pc, get(:pc) + 1) if %i[ld st alu misc].include?(op)
      end
      @values
    end

    private

    def pc
      @values[:pc]
    end

    def audit(arch)
      Const::Audit::ARCH[Const::Audit::ARCH_NAME[arch]]
    end

    def ret(num)
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

    def st(reg, index)
      raise IndexError, "Expect 0 <= index < 16, got: #{index}" unless index.between?(0, 15)

      set(:mem, index, get(reg))
    end

    def jmp(k)
      set(:pc, get(:pc) + k + 1)
    end

    # Emulates cmp instruction.
    def cmp(op, src, jt, jf)
      src = get(:x) if src == :x
      a = get(:a)
      val = a.__send__(op, src)
      val = (val != 0) if val.is_a?(Integer) # handle & operator
      j = val ? jt : jf
      set(:pc, get(:pc) + j + 1)
    end

    def alu(op, src)
      if op == :neg
        set(:a, (2**32) - get(:a))
      else
        src = get(:x) if src == :x
        set(:a, get(:a).__send__(op, src))
      end
    end

    def misc(op)
      case op
      when :txa then set(:a, get(:x))
      when :tax then set(:x, get(:a))
      end
    end

    def set(*arg, val)
      if arg.size == 1
        arg = arg.first
        raise ArgumentError, "Invalid #{arg}" unless %i[a x pc ret].include?(arg)

        @values[arg] = val & 0xffffffff
      else
        raise ArgumentError, arg.to_s unless arg.first == :mem
        raise IndexError, "Invalid index: #{arg[1]}" unless arg[1].between?(0, 15)

        @values[arg[1]] = val & 0xffffffff
      end
    end

    def get(*arg)
      if arg.size == 1
        arg = arg.first
        raise ArgumentError, "Invalid #{arg}" unless %i[a x pc ret].include?(arg)

        undefined(arg.upcase) if @values[arg].nil?
        return @values[arg]
      end
      return @values[arg[1]] if arg.first == :mem

      data_of(arg[1])
    end

    def data_of(index)
      data = Const::BPF::SeccompData
      raise IndexError, "Invalid index: #{index}" unless index.nobits?(3) && index.between?(0, data::SIZE - 1)

      index /= 4
      case index
      when 0 then @sys_nr || undefined(data::NAMES[data::SYS_NUMBER])
      when 1 then @arch || undefined(data::NAMES[data::ARCH])
      when 2, 3 then word_of(@ip || undefined(data::NAMES[data::INSTRUCTION_POINTER]), index)
      else
        val = @args[(index - 4) / 2] || undefined("args[#{(index - 4) / 2}]")
        word_of(val, index)
      end
    end

    # The 32-bit word of the 64-bit value +val+ that lives at word-index +index+ of
    # +seccomp_data+: the high word comes second on little-endian architectures but first on
    # big-endian ones (s390x).
    def word_of(val, index)
      hi = index.odd? ^ @big_endian
      (val >> (hi ? 32 : 0)) & 0xffffffff
    end

    def undefined(var)
      raise format("Undefined Variable\n\t%04d: %s <- `%s` is undefined", pc, @instructions[pc].decompile, var)
    end
  end
end
