# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/explain/qword'
require 'seccomp-tools/util'

module SeccompTools
  class Explain
    # Renders path-condition facts ({Symbolic::Constraint}s and {Qword}s) as C-like conditions,
    # naming the +seccomp_data+ fields and parenthesizing exactly where the expression would
    # otherwise be misread.
    class Renderer
      # C-like operator precedence (higher binds tighter), used to parenthesize a rendered condition
      # exactly where it would otherwise be misread — notably that +==+ binds tighter than the
      # bitwise operators, so +a & b == c+ must be shown as +(a & b) == c+.
      PREC = {
        :* => 12, :/ => 12, :+ => 11, :- => 11, :<< => 10, :>> => 10,
        :< => 9, :<= => 9, :> => 9, :>= => 9, :== => 8, :!= => 8,
        :& => 7, :^ => 6, :| => 5
      }.freeze
      # Unary negation binds tighter than any binary operator.
      UNARY_PREC = 13
      # The comparison operators. When one is the parent, operands are parenthesized by precedence
      # alone (so +a & b == c+ becomes +(a & b) == c+ but +a >> b == c+ stays put), never by the
      # extra readability rule in {#clarity_wrap?}.
      COMPARISON = %i[== != < <= > >=].freeze
      # The +seccomp_data+ field layout the rendered names come from.
      DATA = Const::BPF::SeccompData

      # @param [QwordFusion] fusion
      #   Supplies the endian-correct word offsets of the 64-bit fields, for naming their halves.
      def initialize(fusion)
        @fusion = fusion
      end

      # Renders a conjunction of facts, e.g. +"fd == 0x1 && (flags & 0xf) < 0x5"+.
      # @param [Array<Symbolic::Constraint, Qword>] constraints
      # @param [Symbol?] sys
      #   The syscall the facts belong to, if pinned — names the arguments.
      # @return [String]
      def conjunction(constraints, sys)
        constraints.map do |c|
          if c.is_a?(Qword)
            "#{data_name(@fusion.lo_off(c.base), sys)} #{c.op} 0x#{c.val.to_s(16)}"
          else
            constraint(c, sys)
          end
        end.join(' && ')
      end

      private

      def constraint(c, sys)
        return "(#{binop(:&, c.lhs, c.rhs, sys)}) != 0" if c.op == :set
        return "(#{binop(:&, c.lhs, c.rhs, sys)}) == 0" if c.op == :unset

        prec = PREC[c.op]
        "#{operand(c.lhs, c.op, prec, sys)} #{c.op} #{operand(c.rhs, c.op, prec, sys)}"
      end

      # Renders an expression without any outer parentheses; each caller wraps it via {#operand}.
      def expr(e, sys)
        return '<opaque>' if e.opaque?
        return "0x#{e.val.to_s(16)}" if e.imm?
        return data_name(e.offset, sys) if e.plain_data?
        return "-#{operand(e.lhs, :neg, UNARY_PREC, sys)}" if e.kind == :unop

        binop(e.op, e.lhs, e.rhs, sys)
      end

      # Renders +lhs op rhs+. Operators are left-associative, so the left operand shares +op+'s
      # precedence while the right needs one higher (an equal-precedence right subtree is wrapped).
      def binop(op, lhs, rhs, sys)
        prec = PREC[op]
        left = operand(lhs, op, prec, sys)
        right = rhs.imm? && %i[<< >>].include?(op) ? rhs.val.to_s : operand(rhs, op, prec + 1, sys)
        "#{left} #{op} #{right}"
      end

      # Renders +child+ as an operand of +parent_op+, parenthesizing it when precedence requires it
      # (+child+ binds looser than +min_prec+) or when {#clarity_wrap?} judges the grouping too easy
      # to misread.
      def operand(child, parent_op, min_prec, sys)
        s = expr(child, sys)
        return s unless child.kind == :binop

        PREC[child.op] < min_prec || clarity_wrap?(parent_op, child.op) ? "(#{s})" : s
      end

      # Should a +child_op+ nested under +parent_op+ be parenthesized purely for readability (beyond
      # what precedence requires)? Yes when they sit at *different* precedence levels — mixing
      # families like +a & (b + c)+ or +(a + b) << c+ is easy to misjudge. The exceptions, where the
      # grouping is universally understood, are: any comparison parent (+a & b == c+ is already made
      # unambiguous by wrapping the looser +&+), a same-level pair (+a + b - c+, +a ^ b ^ c+), and
      # multiplication/division directly inside addition/subtraction (+a + b * c+).
      def clarity_wrap?(parent_op, child_op)
        return false if COMPARISON.include?(parent_op)
        return false if PREC[parent_op] == PREC[child_op]
        return false if PREC[child_op] == PREC[:*] && PREC[parent_op] == PREC[:+]

        true
      end

      def data_name(offset, sys)
        case offset
        when DATA::SYS_NUMBER, DATA::ARCH then DATA::NAMES[offset] # the scalar fields
        else qword_word_name(offset, sys) # endian-split fields (instruction_pointer, args)
        end
      end

      # Names one 32-bit word of a 64-bit field, appending +>> 32+ for the high word — which is the
      # second word on little-endian architectures but the first on big-endian ones (s390x).
      def qword_word_name(offset, sys)
        base = @fusion.base_of(offset)
        return "data[#{offset}]" unless DATA::QWORD_BASES.include?(base)

        name = if base == DATA::INSTRUCTION_POINTER
                 DATA::NAMES[base]
               else
                 idx = (base - DATA::ARGS) / 8
                 names = sys && Const::SYS_ARG[sys]
                 Util.colorize((names && names[idx]) || "args[#{idx}]", t: :args)
               end
        offset == @fusion.hi_off(base) ? "#{name} >> 32" : name
      end
    end
  end
end
