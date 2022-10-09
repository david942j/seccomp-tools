# frozen_string_literal: true

require 'seccomp-tools/asm/sasm.tab'
require 'seccomp-tools/asm/scanner'
require 'seccomp-tools/asm/statement'

describe SeccompTools::Asm::SeccompAsmParser do
  let(:scan) { SeccompTools::Asm::Scanner }
  let(:statement) { SeccompTools::Asm::Statement }
  let(:a) { SeccompTools::Asm::Scalar::A.instance }
  let(:x) { SeccompTools::Asm::Scalar::X.instance }
  let(:const_val) { SeccompTools::Asm::Scalar::ConstVal }
  let(:data) { SeccompTools::Asm::Scalar::Data }
  let(:mem) { SeccompTools::Asm::Scalar::Mem }

  describe 'arithmetic' do
    it 'passes normal cases' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A += 0x123
      A -= 0x123
      A *= X
      A /= 0
      A &= 0xffffffff0000
      A |= 0
      A ^= X
      A >>=9
      A <<=  1
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:alu, ['+=', const_val.new(0x123)], []),
        statement.new(:alu, ['-=', const_val.new(0x123)], []),
        statement.new(:alu, ['*=', x], []),
        statement.new(:alu, ['/=', const_val.new(0)], []),
        statement.new(:alu, ['&=', const_val.new(0xffff0000)], []),
        statement.new(:alu, ['|=', const_val.new(0)], []),
        statement.new(:alu, ['^=', x], []),
        statement.new(:alu, ['>>=', const_val.new(9)], []),
        statement.new(:alu, ['<<=', const_val.new(1)], [])
      ]
    end

    it 'passes with embedded new lines' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A     +=
       # a comment
       # another comment

       123 # yet another comment
       # last comment
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:alu, ['+=', const_val.new(123)], [])
      ]
    end

    it 'fails with X' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      X += 0x123
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError)
    end

    it 'fails with args/mem' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A += args[0]
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError)
      scanner = scan.new(<<-EOS, :amd64).validate!
      A += mem[0]
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError)
    end

    it 'fails unsupported operator' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A <= 1
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError)
    end
  end

  describe 'assignment' do
    it 'accepts A as the assignee' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = X
      A = -1
      A = sys_number
      A = read
      A = instruction_pointer
      A = instruction_pointer >> 32
      A = args[0]
      A = args[1]
      A = args[2] >> 32
      A = mem[0]
      A = mem[12]
      A = -A
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:assign, [a, x], []),
        statement.new(:assign, [a, const_val.new(0xffffffff)], []),
        statement.new(:assign, [a, data.new(0)], []),
        statement.new(:assign, [a, const_val.new(0)], []),
        statement.new(:assign, [a, data.new(0x8)], []),
        statement.new(:assign, [a, data.new(0xc)], []),
        statement.new(:assign, [a, data.new(0x10)], []),
        statement.new(:assign, [a, data.new(0x18)], []),
        statement.new(:assign, [a, data.new(0x24)], []),
        statement.new(:assign, [a, mem.new(0)], []),
        statement.new(:assign, [a, mem.new(12)], []),
        statement.new(:assign, [a, :neg], [])
      ]
    end

    it 'raises error on A = <ALU_OP> A' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = +A
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:11 do you mean A = -A?
      A = +A
          ^
      EOS
    end

    it 'catches invalid right shift' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = args[0] >> 5
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:22 operator after an argument can only be '>> 32'
      A = args[0] >> 5
                     ^
      EOS
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = instruction_pointer + 1
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:31 operator after an argument can only be '>> 32'
      A = instruction_pointer + 1
                              ^
      EOS
    end

    it 'accepts X as the assignee' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      X = A
      X = 64
      X = mem[2]
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:assign, [x, a], []),
        statement.new(:assign, [x, const_val.new(64)], []),
        statement.new(:assign, [x, mem.new(2)], [])
      ]
    end

    it 'rejects X = args[]' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      X = sys_number
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:11 unexpected string "sys_number"
      X = sys_number
          ^^^^^^^^^^
      EOS
    end

    it 'accepts mem[] = AX' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      mem[0] = A
      mem[0x0] = X
      mem[0xf] = X
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:assign, [mem.new(0), a], []),
        statement.new(:assign, [mem.new(0), x], []),
        statement.new(:assign, [mem.new(15), x], [])
      ]
    end

    it 'raises an error on invalid mem index' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      mem[16] = A
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:11 index of mem[] must between 0 and 15, got 16
      mem[16] = A
          ^^
      EOS
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = mem[0xaa]
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:15 index of mem[] must between 0 and 15, got 170
      A = mem[0xaa]
              ^^^^
      EOS
    end

    it 'raises an error on invalid args index' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = args[8]
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:16 index of args[] must between 0 and 5, got 8
      A = args[8]
               ^
      EOS
    end
  end

  describe 'conditional' do
    it 'accepts if-else' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      if (A <= X) goto next else goto next

      if (
        A <= X # a comment
      )
        goto next
      else
        goto next
      EOS
      statements = described_class.new(scanner).parse
      expect(statements.size).to be 2
      statements.each do |statement|
        expect(statement.type).to eq :if
        expect(statement.data[0]).to eq ['<=', x]
        expect(statement.data[1].str).to eq 'next'
        expect(statement.data[2].str).to eq 'next'
      end
    end

    it 'accepts if' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      if (A != 0x123) goto label
      EOS
      statement = described_class.new(scanner).parse.first
      expect(statement.type).to eq :if
      expect(statement.data[0]).to eq ['!=', 0x123]
      expect(statement.data[1].str).to eq 'label'
      expect(statement.data[2]).to eq :next
    end

    it 'accepts goto' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      goto label
      EOS
      statement = described_class.new(scanner).parse.first
      expect(statement.type).to eq :if
      expect(statement.data[0]).to be_nil
      expect(statement.data[1].str).to eq 'label'
      expect(statement.data[2].str).to eq 'label'
    end

    it 'accepts ternary operators' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A == X ? next : label
      EOS
      statement = described_class.new(scanner).parse.first
      expect(statement.type).to eq :if
      expect(statement.data[0]).to eq ['==', x]
      expect(statement.data[1].str).to eq 'next'
      expect(statement.data[2].str).to eq 'label'
    end

    it 'supports NOT conditions' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      if (!(A & 0x123)) goto a else goto b
      if (! (A != X)) goto c
      if (!(!(!(!(!(!(A == X))))))) goto d
      EOS
      statements = described_class.new(scanner).parse
      statement = statements[0]
      expect(statement.type).to eq :if
      expect(statement.data[0]).to eq ['&', 0x123]
      expect(statement.data[1].str).to eq 'b'
      expect(statement.data[2].str).to eq 'a'
      statement = statements[1]
      expect(statement.type).to eq :if
      expect(statement.data[0]).to eq ['!=', x]
      expect(statement.data[1]).to eq :next
      expect(statement.data[2].str).to eq 'c'
      statement = statements[2]
      expect(statement.type).to eq :if
      expect(statement.data[0]).to eq ['==', x]
      expect(statement.data[1].str).to eq 'd'
      expect(statement.data[2]).to eq :next
    end
  end

  describe 'return' do
    it 'accepts A' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      return A
      EOS
      expect(described_class.new(scanner).parse).to eq [statement.new(:ret, a, [])]
    end

    it 'accepts const' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      return 0x123
      EOS
      expect(described_class.new(scanner).parse).to eq [statement.new(:ret, 0x123, [])]
    end

    it 'accepts actions' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      return KILL_PROCESS
      return KILL_THREAD
      return KILL
      return TRAP
      return ERRNO
      return USER_NOTIF
      return LOG
      return TRACE
      return ALLOW
      EOS
      res = SeccompTools::Const::BPF::ACTION.map { |_, v| statement.new(:ret, v, []) }
      expect(described_class.new(scanner).parse).to eq res
    end

    it 'accepts actions with data' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      return ERRNO(0x1234)
      return TRAP(0xfabcd)
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:ret, 0x51234, []),
        statement.new(:ret, 0x3abcd, [])
      ]
    end
  end

  describe 'constexpr' do
    it 'accepts parentheses' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      return (123)
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:ret, 123, [])
      ]
    end

    it 'accepts syscalls' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = read
      A = aarch64.read
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:assign, [a, const_val.new(0)], []),
        statement.new(:assign, [a, const_val.new(63)], [])
      ]
    end

    it 'raises on non-existing syscalls' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = aarch64.open
      EOS
      expect { described_class.new(scanner).parse }.to raise_error SeccompTools::ParseError, <<-EOS
<inline>:1:11 syscall 'open' doesn't exist on aarch64
      A = aarch64.open
          ^^^^^^^^^^^^
      EOS
    end
  end

  describe 'labels' do
    it 'accepts multiple labels' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      line1:
      goto next
      label1: label2: goto next
      multi1:
      multi2: multi3: goto next
      EOS
      expect(described_class.new(scanner).parse.map { |s| s.symbols.map(&:str) }).to eq [
        %w[line1],
        %w[label1 label2],
        %w[multi1 multi2 multi3]
      ]
    end

    it 'raises an error with a trailing label' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      goto oob
      oob:
      EOS
      expect { described_class.new(scanner).parse }.to raise_error SeccompTools::ParseError, <<-EOS
<inline>:2:11 unexpected string "\\n"
      oob:
          ^
      EOS
    end

    it 'reserves label next' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      next: A = 1
      EOS
      expect { described_class.new(scanner).parse }.to raise_error SeccompTools::ParseError, <<-EOS
<inline>:1:7 'next' is a reserved label
      next: A = 1
      ^^^^
      EOS
    end
  end

  it 'calls reduce_none' do
    # For unknown reasons the function is never called. Call it here to increase test coverage.
    expect(described_class.new(nil)._reduce_none([1], nil)).to eq 1
  end

  it 'accepts empty input' do
    scanner = scan.new('', :amd64).validate!
    expect(described_class.new(scanner).parse).to be_empty
  end
end
