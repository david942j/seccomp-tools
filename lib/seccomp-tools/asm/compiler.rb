# frozen_string_literal: true

require 'seccomp-tools/asm/tokenizer'
require 'seccomp-tools/bpf'
require 'seccomp-tools/const'

module SeccompTools
  module Asm
    # @private
    #
    # Compile seccomp rules.
    class Compiler
      # Instantiate a {Compiler} object.
      #
      # @param [Symbol] arch
      #   Architecture.
      def initialize(arch)
        @arch = arch
        @insts = []
        @labels = {}
        @insts_linenum = {}
        @input = []
      end

      # Before compile assembly codes, process each lines.
      #
      # With this we can support label in seccomp rules.
      # @param [String] line
      #   One line of seccomp rule.
      # @return [void]
      def process(line)
        @input << line.strip
        line = remove_comment(line)
        @token = Tokenizer.new(line)
        return if line.empty?

        begin
          res = case line
                when /\?/ then cmp
                when /^#{Tokenizer::LABEL_REGEXP}:/ then define_label
                when /^return/ then ret
                when /^(A|X)\s*=[^=]/ then assign
                when /^mem\[\d+\]\s*=\s*(A|X)/ then store
                when /^A\s*.{1,2}=/ then alu
                when /^(goto|jmp|jump)/ then jmp_abs
                end
        rescue ArgumentError => e
          invalid(@input.size - 1, e.message)
        end
        invalid(@input.size - 1) if res.nil?
        if res.first == :label
          @labels[res.last] = @insts.size
        else
          @insts << res
          @insts_linenum[@insts.size - 1] = @input.size - 1
        end
      end

      # Compiles the processed instructions.
      #
      # @return [Array<SeccompTools::BPF>]
      #   Returns the compiled {BPF} array.
      # @raise [ArgumentError]
      #   Raises the error found during compilation.
      def compile!
        @insts.map.with_index do |inst, idx|
          @line = idx
          case inst.first
          when :assign then compile_assign(inst[1], inst[2])
          when :alu then compile_alu(inst[1], inst[2])
          when :ret then compile_ret(inst[1])
          when :cmp then compile_cmp(inst[1], inst[2], inst[3], inst[4])
          when :jmp_abs then compile_jmp_abs(inst[1])
          end
        end
      rescue ArgumentError => e
        invalid(@insts_linenum[@line], e.message)
      end

      private

      # Emits a raw BPF object.
      #
      # @return [BPF]
      #   Returns the emitted {BPF} object.
      def emit(*args, k: 0, jt: 0, jf: 0)
        code = 0
        # bad idea, but keys are not duplicated so this is ok.
        args.each do |a|
          code |= Const::BPF::COMMAND.fetch(a, 0)
          code |= Const::BPF::JMP.fetch(a, 0)
          code |= Const::BPF::SRC.fetch(a, 0)
          code |= Const::BPF::MODE.fetch(a, 0)
          code |= Const::BPF::OP.fetch(a, 0)
          code |= Const::BPF::MISCOP.fetch(a, 0)
        end
        BPF.new({ code: code, k: k, jt: jt, jf: jf }, @arch, @line)
      end

      # A = X / X = A
      # mem[i] = <A|X>
      # <A|X> = 123|sys_const
      # A = len
      # <A|X> = mem[i]
      # A = args_h[i]|args[i]|sys_number|arch
      # A = data[4 * i]
      def compile_assign(dst, src)
        # misc txa / tax
        return compile_assign_misc(dst, src) if (dst == :a && src == :x) || (dst == :x && src == :a)
        # case of st / stx
        return emit(src == :x ? :stx : :st, k: dst.last) if dst.is_a?(Array) && dst.first == :mem

        src = evaluate(src)
        ld = dst == :x ? :ldx : :ld
        # <A|X> = <immi>
        return emit(ld, :imm, k: src) if src.is_a?(Integer)
        # now src must be in form [:len/:mem/:data, num]
        return emit(ld, src.first, k: src.last) if src.first == :mem || src.first == :len
        # check if num is multiple of 4
        raise ArgumentError, 'Index of data[] must be a multiple of 4' if src.last % 4 != 0

        emit(ld, :abs, k: src.last)
      end

      def compile_assign_misc(dst, _src)
        emit(:misc, dst == :a ? :txa : :tax)
      end

      def compile_alu(op, val)
        val = evaluate(val)
        src = val == :x ? :x : :k
        val = 0 if val == :x
        emit(:alu, op, src, k: val)
      end

      def compile_ret(val)
        if val == :a
          src = :a
          val = 0
        end
        emit(:ret, src, k: val)
      end

      def compile_jmp_abs(target)
        targ = label_offset(target)
        emit(:jmp, :ja, k: targ)
      end

      # Compiles comparsion.
      def compile_cmp(op, val, jt, jf)
        jt = label_offset(jt)
        jf = label_offset(jf)
        val = evaluate(val)
        src = val == :x ? :x : :k
        val = 0 if val == :x
        emit(:jmp, op, src, jt: jt, jf: jf, k: val)
      end

      def label_offset(label)
        return label if label.is_a?(Integer)
        return 0 if label == 'next'
        raise ArgumentError, "Undefined label #{label.inspect}" if @labels[label].nil?
        raise ArgumentError, "Does not support backward jumping to #{label.inspect}" if @labels[label] < @line

        @labels[label] - @line - 1
      end

      def evaluate(val)
        return val if val.is_a?(Integer) || val == :x || val == :a

        # keywords
        val = case val
              when 'sys_number' then [:data, 0]
              when 'arch' then [:data, 4]
              when 'len' then [:len, 0]
              else val
              end
        return eval_constants(val) if val.is_a?(String)

        # remains are [:mem/:data/:args/:args_h, <num>]
        # first convert args to data
        val = [:data, val.last * 8 + 16] if val.first == :args
        val = [:data, val.last * 8 + 20] if val.first == :args_h
        val
      end

      def eval_constants(str)
        Const::Syscall.const_get(@arch.upcase.to_sym)[str.to_sym] ||
          Const::Audit::ARCH[str] ||
          raise(ArgumentError, "Invalid constant: #{str.inspect}")
      end

      attr_reader :token

      # <goto|jmp|jump> <label|Integer>
      def jmp_abs
        token.fetch('goto') ||
          token.fetch('jmp') ||
          token.fetch('jump') ||
          raise(ArgumentError, 'Invalid jump alias: ' + token.cur.inspect)
        target = token.fetch!(:goto)
        [:jmp_abs, target]
      end

      # A <comparison> <sys_str|X|Integer> ? <label|Integer> : <label|Integer>
      def cmp
        token.fetch!('A')
        op = token.fetch!(:comparison)
        dst = token.fetch!(:sys_num_x)
        token.fetch!('?')
        jt = token.fetch!(:goto)
        token.fetch!(':')
        jf = token.fetch!(:goto)
        convert = {
          :< => :>=,
          :<= => :>,
          :!= => :==
        }
        if convert[op]
          op = convert[op]
          jt, jf = jf, jt
        end
        op = {
          :>= => :jge,
          :> => :jgt,
          :== => :jeq
        }[op]
        [:cmp, op, dst, jt, jf]
      end

      def ret
        token.fetch!('return')
        [:ret, token.fetch!(:ret)]
      end

      # possible types after '=':
      #   A = X
      #   X = A
      #   A = 123
      #   A = data[i]
      #   A = mem[i]
      #   A = args[i]
      #   A = sys_number|arch
      #   A = len
      def assign
        dst = token.fetch!(:ax)
        token.fetch!('=')
        src = token.fetch(:ax) ||
              token.fetch(:sys_num_x) ||
              token.fetch(:ary) ||
              token.fetch('sys_number') ||
              token.fetch('arch') ||
              token.fetch('len') ||
              raise(ArgumentError, 'Invalid source: ' + token.cur.inspect)
        [:assign, dst, src]
      end

      # returns same format as assign
      def store
        [:assign, token.fetch!(:ary), token.fetch!('=') && token.fetch!(:ax)]
      end

      def define_label
        name = token.fetch!(:goto)
        token.fetch(':')
        [:label, name]
      end

      # A op= sys_num_x
      # TODO: support A = -A
      def alu
        token.fetch!('A')
        op = token.fetch!(:alu_op)
        token.fetch!('=')
        src = token.fetch!(:sys_num_x)
        [:alu, op, src]
      end

      def remove_comment(line)
        line = line.to_s.dup
        line.slice!(/#.*\Z/m)
        line.strip
      end

      def invalid(line, extra_msg = nil)
        message = "Invalid instruction at line #{line + 1}: #{@input[line].inspect}"
        message += "\n" + 'Error: ' + extra_msg if extra_msg
        raise ArgumentError, message
      end
    end
  end
end
