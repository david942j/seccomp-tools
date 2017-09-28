require 'seccomp-tools/asm/tokenizer'

describe SeccompTools::Asm::Tokenizer do
  describe 'fetch' do
    it 'str' do
      token = described_class.new('meow meow')
      expect(token.fetch!('meow')).to eq 'meow'
    end

    it 'sys_num_x' do
      token = described_class.new('X 123456 read write getdents64 getdents')
      expect(token.fetch!(:sys_num_x)).to eq :x
      expect(token.fetch!(:sys_num_x)).to eq 123_456
      expect(token.fetch!(:sys_num_x)).to eq 'read'
      expect(token.fetch!(:sys_num_x)).to eq 'write'
      expect(token.fetch!(:sys_num_x)).to eq 'getdents64'
      expect(token.fetch!(:sys_num_x)).to eq 'getdents'
    end

    it 'comparison' do
      token = described_class.new('< < > == <= >= !=')
      expect(token.fetch!(:comparison)).to eq :<
      expect(token.fetch!(:comparison)).to eq :<
      expect(token.fetch!(:comparison)).to eq :>
      expect(token.fetch!(:comparison)).to eq :==
      expect(token.fetch!(:comparison)).to eq :<=
      expect(token.fetch!(:comparison)).to eq :>=
      expect(token.fetch!(:comparison)).to eq :!=
    end

    it 'goto' do
      token = described_class.new('456 oao_1 _kill_2')
      expect(token.fetch!(:goto)).to eq 456
      expect(token.fetch!(:goto)).to eq 'oao_1'
      expect(token.fetch!(:goto)).to eq '_kill_2'
    end

    it 'ret' do
      token = described_class.new('A ALLOW KILL ERRNO(123) TRAP TRACE MEOW')
      expect(token.fetch!(:ret)).to eq :a
      expect(token.fetch!(:ret)).to eq 0x7fff0000
      expect(token.fetch!(:ret)).to eq 0x00000000
      expect(token.fetch!(:ret)).to eq 0x0005007b
      expect(token.fetch!(:ret)).to eq 0x00030000
      expect(token.fetch!(:ret)).to eq 0x7ff00000
      expect { token.fetch!(:ret) }.to raise_error(ArgumentError, "Invalid return type: \"MEOW\".\n")
    end

    it 'ax' do
      token = described_class.new('A X meow')
      expect(token.fetch!(:ax)).to eq :a
      expect(token.fetch!(:ax)).to eq :x
      expect { token.fetch!(:ax) }.to raise_error(ArgumentError, "Expected 'A' or 'X', while \"meow\" occured.\n")
      expect(token.fetch(:ax)).to be nil
    end

    it 'ary' do
      token = described_class.new('data[0] data[13] mem[9] args[1]')
      expect(token.fetch!(:ary)).to eq [:data, 0]
      expect(token.fetch!(:ary)).to eq [:data, 13]
      expect(token.fetch!(:ary)).to eq [:mem, 9]
      expect(token.fetch!(:ary)).to eq [:args, 1]
    end

    it 'alu_op' do
      token = described_class.new('+ - * / | & << >> ^')
      expect(token.fetch!(:alu_op)).to eq :add
      expect(token.fetch!(:alu_op)).to eq :sub
      expect(token.fetch!(:alu_op)).to eq :mul
      expect(token.fetch!(:alu_op)).to eq :div
      expect(token.fetch!(:alu_op)).to eq :or
      expect(token.fetch!(:alu_op)).to eq :and
      expect(token.fetch!(:alu_op)).to eq :lsh
      expect(token.fetch!(:alu_op)).to eq :rsh
      expect(token.fetch!(:alu_op)).to eq :xor
    end

    it 'invalid' do
      token = described_class.new('whatever')
      expect { token.fetch!(:meow) }.to raise_error(ArgumentError, 'Unsupported type: :meow')
    end
  end
end
