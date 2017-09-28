require 'seccomp-tools/asm/tokenizer'
require 'seccomp-tools/bpf'
require 'seccomp-tools/const'

module SeccompTools
  module Asm
    # Compile seccomp rules.
    class Compiler
      def initialize(arch)
        @arch = arch
        @insts = []
        @labels = {}
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
                when /^A\s*.=/ then alu
                end
        rescue ArgumentError => e
          invalid(@input.size - 1, e.message)
        end
        invalid(@input.size - 1) if res.nil?
        if res.first == :label
          @labels[res.last] = @insts.size
        else
          @insts << res
        end
        res
      end

      # @return [Array<SeccompTools::BPF>]
      def compile!
        @insts.map.with_index do |inst, idx|
          @line = idx
          case inst.first
          when :assign then compile_assign(inst[1], inst[2])
          when :alu then compile_alu(inst[1], inst[2])
          when :ret then compile_ret(inst[1])
          when :cmp then compile_cmp(inst[1], inst[2], inst[3], inst[4])
          end
        end
      rescue ArgumentError => e
        invalid(@line, e.message)
      end

      private

      def emit(*args, k: 0, jt: 0, jf: 0)
        code = 0
        # bad idea, while keys are not duplicated so this is ok.
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
      # <A|X> = mem[i]
      # <A|X> = 123|sys_const
      # A = args[i]|sys_number|arch
      # A = data[4 * i]
      def compile_assign(dst, src)
        # misc txa / tax
        return emit(:misc, :txa) if dst == :a && src == :x
        return emit(:misc, :tax) if dst == :x && src == :a
        src = evaluate(src)
        # TODO: handle store case.
        ld = dst == :x ? :ldx : :ld
        # <A|X> = <immi>
        return emit(ld, :imm, k: src) if src.is_a?(Integer)
        # now src must be in form [:mem/:data, num]
        return emit(ld, :mem, k: src.last) if src.first == :mem
        # check if num is multiple of 4
        raise ArgumentError, 'Index of data[] must be multiplication of 4' if src.last % 4 != 0
        emit(ld, :abs, k: src.last)
      end

      def compile_alu(op, val)
        val = evaluate(val)
        src = val == :x ? :x : :k
        val = 0 if val == :x
        emit(:alu, op, src, k: val)
      end

      def compile_ret(val)
        emit(:ret, k: val)
      end

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
        @labels[label] - @line - 1
      end

      def evaluate(val)
        return val if val.is_a?(Integer) || val == :x
        # keywords
        val = case val
              when 'sys_number' then [:data, 0]
              when 'arch' then [:data, 4]
              else val
              end
        return Const::Syscall.const_get(@arch.upcase.to_sym)[val.to_sym] if val.is_a?(String)
        # remains are [:mem/:data/:args, <num>]
        # first convert args to data
        val = [:data, val.last * 8 + 16] if val.first == :args
        val
      end

      attr_reader :token

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
      def assign
        dst = token.fetch!(:ax)
        token.fetch!('=')
        src = token.fetch(:ax) ||
              token.fetch(:sys_num_x) ||
              token.fetch(:ary) ||
              token.fetch('sys_number') ||
              token.fetch('arch')
        [:assign, dst, src]
      end

      def define_label
        name = token.fetch!(:goto)
        token.fetch(':')
        [:label, name]
      end

      # A op= sys_num_x
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
