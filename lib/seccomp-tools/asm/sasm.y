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
            raise_error { |t| "'next' is a reserved label" } if t == 'next'
            t
          }
  statement: arithmetic { [:alu, val[0]] }
           | assignment { [:assign, val[0]] }
           | conditional { [:if, val[0]] }
           | return_stat { [:ret, val[0]] }
           | goto_expr { [:if, [0, val[0], val[0]]] }
  # TODO: A = -A
  arithmetic: A ALU_OP newlines x_constexpr { [val[1], val[3]] }
  assignment: a ASSIGN rval { [val[0], val[2]] }
            | x ASSIGN a { [val[0], val[2]] }
            | memory ASSIGN ax { [[:mem, val[0]], val[2]] }
  rval: x_constexpr { val[0] }
      | argument { [:arg, val[0]] }
      | memory { [:mem, val[0]] }
  conditional: IF comparison newlines goto_expr newlines else_block { [val[1], val[3], val[5]] }
  else_block: ELSE newlines goto_expr { val[2] }
            | { 'next' }
  comparison: LPAREN newlines a newlines COMPARE newlines x_constexpr newlines RPAREN { [val[4], val[6]] }
  goto_expr: GOTO GOTO_SYMBOL { val[1] }
  return_stat: RETURN ret_val { val[1] }
  ret_val: a
         | ACTION { Const::BPF::ACTION[val[0].to_sym] }
         | ACTION LPAREN constexpr RPAREN {
             Const::BPF::ACTION[val[0].to_sym] |
               (val[2] & Const::BPF::SECCOMP_RET_DATA)
           }
         | constexpr
  memory: MEM LBRACK constexpr RBRACK { val[2] }
  x_constexpr: x
             | constexpr
  argument: argument_long
          | argument_long '>>' constexpr { val[0] + 4 } # TODO
          | SYS_NUMBER { 0 }
          | ARCH { 4 }
  # 8-byte long arguments
  argument_long: ARGS LBRACK constexpr RBRACK { 16 + val[2] * 8 }
               | INSTRUCTION_POINTER { 8 }
  constexpr: number { val[0] & 0xffffffff }
           | LPAREN constexpr RPAREN { val[1] }
  ax: a
     | x
  a: A { :A }
  x: X { :X }
  number: INT { val[0].to_i }
        | HEX_INT { val[0].to_i(16) }
        | ARCH_VAL { Const::Audit::ARCH[val[0]] }
        | SYSCALL { @scanner.syscalls[val[0].to_sym] }
  terminator: newlines
            | false
  newlines: newlines NEWLINE
          |
  ASSIGN: '='
  LPAREN: '('
  RPAREN: ')'
  LBRACK: '['
  RBRACK: ']'
end

---- header
require 'seccomp-tools/asm/scanner'
require 'seccomp-tools/asm/statement'

---- inner
  def initialize(scanner)
    @scanner = scanner
    super()
  end

  def parse
    @tokens = @scanner.scan.dup
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
    raise_error { |token| "unexpect string #{token.str.inspect}" }
  end

  # @private
  def raise_error
    token = @tokens[@cur_idx - 1]
    raise SeccompTools::ParseError, @scanner.format_error(token, yield(token))
  end

---- footer
