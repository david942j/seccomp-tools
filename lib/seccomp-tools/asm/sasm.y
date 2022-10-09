class SeccompTools::Asm::SeccompAsmParser
  options no_result_var
rule
  prog: normalized_statement terminator { [val[0]] }
      | prog normalized_statement terminator { val[0] << val[1] }
  normalized_statement: symbols newlines statement { Statement.new(*val[2], val[0]) }
                      | statement { Statement.new(*val[0], []) }
  symbols: symbol { val }
         | symbols newlines symbol { val[0] << val[2] }
  symbol: SYMBOL {
            t = val[0]
            raise_error("'next' is a reserved label") if t == 'next'
            last_token
          }
  statement: arithmetic { [:alu, val[0]] }
           | assignment { [:assign, val[0]] }
           | conditional { [:if, val[0]] }
           | goto_expr { [:if, [nil, val[0], val[0]]] }
           | return_stat { [:ret, val[0]] }
  arithmetic: A alu_op_eq newlines x_constexpr { [val[1], val[3]] }
  assignment: a ASSIGN a_rval { [val[0], val[2]] }
            | x ASSIGN x_rval { [val[0], val[2]] }
            | memory ASSIGN ax { [val[0], val[2]] }
  # X = ?
  x_rval: constexpr
        | memory
        | a
  # A = ?
  a_rval: x_constexpr
        | argument { Scalar::Data.new(val[0]) }
        | memory
        | LEN { Scalar::Len.instance }
        # A = -A is a special case, it's in an assignment form but belongs to ALU BPF
        | ALU_OP A {
          raise_error('do you mean A = -A?', -1) if val[0] != '-'
          :neg
        }
  conditional: IF comparison newlines goto_expr newlines else_block {
                 op, rval, parity = val[1]
                 jt, jf = val[3], val[5]
                 jt, jf = jf, jt if parity.odd?
                 [[op, rval], jt, jf]
               }
             | A compare x_constexpr goto_symbol goto_symbol { [[val[1], val[2]], val[3], val[4]] }
  else_block: ELSE newlines goto_expr { val[2] }
            | { :next }
  comparison: LPAREN newlines comparison_ newlines RPAREN { val[2] }
  comparison_: a newlines compare newlines x_constexpr { [val[2], val[4], 0] }
             | BANG LPAREN comparison_ RPAREN { val[2][2] += 1; val[2] }
  compare: COMPARE
         | AND
  goto_expr: GOTO goto_symbol { val[1] }
  goto_symbol: GOTO_SYMBOL { last_token }
  return_stat: RETURN ret_val { val[1] }
  ret_val: a
         | ACTION { Scalar::ConstVal.new(Const::BPF::ACTION[val[0].to_sym]) }
         | ACTION LPAREN constexpr RPAREN {
             Scalar::ConstVal.new(Const::BPF::ACTION[val[0].to_sym] |
               (val[2].to_i & Const::BPF::SECCOMP_RET_DATA))
           }
         | constexpr
  memory: MEM LBRACK constexpr RBRACK {
            idx = val[2].to_i
            raise_error(format("index of mem[] must between 0 and 15, got %d", idx), -1) unless idx.between?(0, 15)
            Scalar::Mem.new(idx)
          }
  x_constexpr: x
             | constexpr
  argument: argument_long
          | argument_long alu_op INT {
              if val[1] != '>>' || val[2].to_i != 32
                off = val[1] == '>>' ? 0 : -1
                raise_error("operator after an argument can only be '>> 32'", off)
              end
              val[0] + 4
            }
          | SYS_NUMBER { 0 }
          | ARCH { 4 }
          | DATA LBRACK constexpr RBRACK {
              idx = val[2].to_i
              if idx % 4 != 0 || idx >= 64
                raise_error(format('index of data[] must be a multiple of 4 and less than 64, got %d', idx), -1)
              end
              idx
            }
  # 8-byte long arguments
  argument_long: args LBRACK constexpr RBRACK {
                   idx = val[2].to_i
                   s = val[0]
                   raise_error(format('index of %s[] must between 0 and 5, got %d', s, idx), -1) unless idx.between?(0, 5)
                   16 + idx * 8 + (s.downcase.end_with?('h') ? 4 : 0)
                 }
               | INSTRUCTION_POINTER { 8 }
  args: ARGS
      | ARGS_H
  alu_op_eq: alu_op ASSIGN { val[0] + val[1] }
  alu_op: ALU_OP
        | AND
  constexpr: number { Scalar::ConstVal.new(val[0] & 0xffffffff) }
           | LPAREN constexpr RPAREN { val[1] }
  ax: a
     | x
  a: A { Scalar::A.instance }
  x: X { Scalar::X.instance }
  number: INT { val[0].to_i }
        | HEX_INT { val[0].to_i(16) }
        | ARCH_VAL { Const::Audit::ARCH[val[0]] }
        | SYSCALL {
            s = val[0]
            return @scanner.syscalls[s.to_sym] unless s.include?('.')

            arch, sys = s.split('.')
            Const::Syscall.const_get(arch.upcase)[sys.to_sym].tap do |v|
              raise_error("syscall '#{sys}' doesn't exist on #{arch}") if v.nil?
            end
          }
  terminator: newlines
            | false
  newlines: newlines NEWLINE
          |
  ASSIGN: '='
  LPAREN: '('
  RPAREN: ')'
  LBRACK: '['
  RBRACK: ']'
  AND: '&'
  BANG: '!'
end

---- header
require 'seccomp-tools/asm/scalar'
require 'seccomp-tools/asm/scanner'
require 'seccomp-tools/asm/statement'

---- inner
  def initialize(scanner)
    @scanner = scanner
    super()
  end

  # @return [Array<Statement>]
  def parse
    @tokens = @scanner.scan.dup
    return [] if @tokens.empty?

    @cur_idx = 0
    do_parse
  end

  def next_token
    token = @tokens[@cur_idx]
    return [false, '$'] if token.nil?

    @cur_idx += 1
    [token.sym, token.str]
  end

  def on_error(t, val, vstack)
    raise_error("unexpected string #{last_token.str.inspect}")
  end

  # @param [String] msg
  # @param [Integer] offset
  # @private
  def raise_error(msg, offset = 0)
    raise SeccompTools::ParseError, @scanner.format_error(last_token(offset), msg)
  end

  # @param [Integer] off
  #   0 for the last parsed token, -n for the n-th previous parsed token, n for the future n-th token.
  def last_token(off = 0)
    @tokens[@cur_idx - 1 + off]
  end

---- footer
