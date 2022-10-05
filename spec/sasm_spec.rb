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
      # TODO: A = instruction_pointer >> 4
      A = instruction_pointer
      A = args[0]
      A = args[1]
      A = mem[0]
      A = mem[12]
      EOS
      expect(described_class.new(scanner).parse).to eq [
        statement.new(:assign, [a, x], []),
        statement.new(:assign, [a, const_val.new(0xffffffff)], []),
        statement.new(:assign, [a, data.new(0)], []),
        statement.new(:assign, [a, const_val.new(3)], []),
        statement.new(:assign, [a, data.new(0x8)], []),
        statement.new(:assign, [a, data.new(0x10)], []),
        statement.new(:assign, [a, data.new(0x18)], []),
        statement.new(:assign, [a, mem.new(0)], []),
        statement.new(:assign, [a, mem.new(12)], [])
      ]
    end

    it 'accepts x = a' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      X = A
      x =a
      X=a
      x= A
      EOS
      expect(described_class.new(scanner).parse).to eq [statement.new(:assign, [x, a], [])] * 4
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
<inline>:1:11 Index of mem[] must between 0 and 15, got 16
      mem[16] = A
          ^^
      EOS
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = mem[0xaa]
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:15 Index of mem[] must between 0 and 15, got 170
      A = mem[0xaa]
              ^^^^
      EOS
    end

    it 'raises an error on invalid args index' do
      scanner = scan.new(<<-EOS, :amd64).validate!
      A = args[8]
      EOS
      expect { described_class.new(scanner).parse }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:16 Index of args[] must between 0 and 5, got 8
      A = args[8]
               ^
      EOS
    end
  end

  it 'reduce none' do
    # For unknown reasons the function is never called. Call it here to increase test coverage.
    expect(described_class.new(nil)._reduce_none([1], nil)).to eq 1
  end
end
