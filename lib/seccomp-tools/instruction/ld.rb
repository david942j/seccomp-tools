require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction ld.
    class LD < Base
      # Decompile instruction.
      def decompile
        ret = reg + ' = '
        type = load_val
        return ret + type[:val].to_s if type[:rel] == :immi
        return ret + "mem[#{type[:val]}]" if type[:rel] == :mem
        # what happend if len with BPF_B ?
        ret + seccomp_data_str.to_s
      end

      # Accumulator register.
      # @return ['A']
      def reg
        'A'
      end

      def emulate(context)
        nctx = context.dup
        type = load_val
        nctx[reg] = case type[:rel]
                    when :immi then type[:val]
                    when :mem then context.mem[type[:val]]
                    when :data then [:data, type[:val]]
                    end
        [[line + 1, nctx]]
      end

      private

      def mode
        @mode ||= MODE.invert[code & 0xe0]
        # Seccomp doesn't support this mode
        invalid if @mode.nil? || @mode == :ind
        @mode
      end

      def load_val
        return { rel: :immi, val: k } if mode == :imm
        return { rel: :immi, val: SIZEOF_SECCOMP_DATA } if mode == :len
        return { rel: :mem, val: k } if mode == :mem
        { rel: :data, val: k }
      end

      # struct seccomp_data {
      #   int nr;
      #   __u32 arch;
      #   __u64 instruction_pointer;
      #   __u64 args[6];
      # };
      def seccomp_data_str
        case k
        when 0 then 'sys_number'
        when 4 then 'arch'
        when 8 then 'instruction_pointer'
        else
          idx = Array.new(6) { |i| i * 8 + 16 }.index(k)
          idx.nil? ? "data[#{k}]" : "args[#{idx}]"
        end
      end
    end
  end
end
