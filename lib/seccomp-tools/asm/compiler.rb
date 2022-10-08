# frozen_string_literal: true

require 'seccomp-tools/asm/sasm.tab'
require 'seccomp-tools/asm/scalar'
require 'seccomp-tools/asm/scanner'
require 'seccomp-tools/bpf'
require 'seccomp-tools/error'

module SeccompTools
  module Asm
    # @private
    #
    # Compile seccomp rules.
    class Compiler
      # Instantiate a {Compiler} object.
      #
      # @param [String] source
      #   Input string.
      # @param [String?] filename
      #   Only used in error messages.
      # @param [Symbol] arch
      #   Architecture.
      def initialize(source, filename, arch)
        @scanner = Scanner.new(source, arch, filename: filename)
        @arch = arch
        @symbols = {}
      end

      # Compiles the processed instructions.
      #
      # @return [Array<SeccompTools::BPF>]
      #   Returns the compiled {BPF} array.
      # @raise [SeccompTools::Error]
      #   Raises the error found during compilation.
      def compile!
        @scanner.validate!
        statements = SeccompAsmParser.new(@scanner).parse
        fixup_symbols(statements)
        resolve_symbols(statements)

        statements.map.with_index do |s, idx|
          @line = idx
          case s.type
          when :alu then emit_alu(*s.data)
          when :assign then emit_assign(*s.data)
          when :if then emit_cmp(*s.data)
          when :ret then emit_ret(*s.data)
          end
        end
      end

      private

      def fixup_symbols(statements)
        statements.each_with_index do |statement, idx|
          statement.symbols.uniq(&:str).each do |s|
            if @symbols[s.str]
              msg = @scanner.format_error(s, "duplicate label '#{s.str}'")
              msg += @scanner.format_error(@symbols[s.str][0], 'previously defined here')
              raise SeccompTools::DuplicateLabelError, msg
            end

            @symbols[s.str] = [s, idx]
          end
        end
      end

      def resolve_symbols(statements)
        statements.each_with_index do |statement, idx|
          next if statement.type != :if

          jt = resolve_symbol(idx, statement.data[1])
          jf = resolve_symbol(idx, statement.data[2])
          statement.data[1] = jt
          statement.data[2] = jf
        end
      end

      # @param [Integer] index
      # @param [SeccompTools::Asm::Token, :next] sym
      def resolve_symbol(index, sym)
        return 0 if sym.is_a?(Symbol) && sym == :next

        str = sym.str
        return 0 if str == 'next'

        if @symbols[str].nil?
          # special case - goto <n> can be considered as $+1+<n>
          return str.to_i if str == str.to_i.to_s

          raise SeccompTools::UndefinedLabelError,
                @scanner.format_error(sym, "Cannot find label '#{str}'")
        end
        if @symbols[str][1] <= index
          raise SeccompTools::BackwardJumpError,
                @scanner.format_error(sym,
                                      "Does not support backward jumping to '#{str}'")
        end

        @symbols[str][1] - index - 1
      end

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

      # A = -A
      # A = X / X = A
      # mem[i] = <A|X>
      # A = len
      # <A|X> = <immi|mem[i]|data[i]>
      def emit_assign(dst, src)
        return emit(:alu, :neg) if src.is_a?(Symbol) && src == :neg
        # misc txa / tax
        return emit(:misc, dst.a? ? :txa : :tax) if (dst.a? && src.x?) || (dst.x? && src.a?)
        # case of st / stx
        return emit(src.x? ? :stx : :st, k: dst.val) if dst.mem?

        emit_ld(dst, src)
      end

      def emit_ld(dst, src)
        ld = dst.x? ? :ldx : :ld
        return emit(ld, :len, k: 0) if src.len?
        return emit(ld, :imm, k: src.to_i) if src.const?
        return emit(ld, :mem, k: src.val) if src.mem?

        emit(ld, :abs, k: src.val) if src.data?
      end

      def emit_alu(op, val)
        src, k = val.x? ? [:x, 0] : [:k, val.to_i]
        emit(:alu, convert_alu_op(op), src, k: k)
      end

      def convert_alu_op(op)
        {
          '+' => :add,
          '-' => :sub,
          '*' => :mul,
          '/' => :div,
          '|' => :or,
          '&' => :and,
          '<<' => :lsh,
          '>>' => :rsh,
          '^' => :xor
        }[op[0..-2]]
      end

      def emit_ret(val)
        if val.a?
          src = :a
          val = 0
        end
        emit(:ret, src, k: val.to_i)
      end

      def emit_cmp(cmp, jt, jf)
        jop, jt, jf = convert_jmp_op(cmp, jt, jf)
        return emit(:jmp, jop, 0, jt: 0, jf: 0, k: jt) if jop == :ja || jt == jf

        val = cmp[1]
        src = val.x? ? :x : :k
        k = val.x? ? 0 : val.to_i
        emit(:jmp, jop, src, jt: jt, jf: jf, k: k)
      end

      # == != >= <= > < &
      def convert_jmp_op(cmp, jt, jf)
        return [:ja, jt, jf] if cmp.nil?

        case cmp[0]
        when '==' then [:jeq, jt, jf]
        when '!=' then [:jeq, jf, jt]
        when '>=' then [:jge, jt, jf]
        when '<=' then [:jgt, jf, jt]
        when '>' then [:jgt, jt, jf]
        when '<' then [:jge, jf, jt]
        when '&' then [:jset, jt, jf]
        end
      end
    end
  end
end
