# frozen_string_literal: true

require 'seccomp-tools/explain/qword'
require 'seccomp-tools/explain/renderer'
require 'seccomp-tools/symbolic/constraint'
require 'seccomp-tools/symbolic/expr'
require 'seccomp-tools/util'

describe SeccompTools::Explain::Renderer do
  before { SeccompTools::Util.disable_color! }

  def e = SeccompTools::Symbolic::Expr
  def c = SeccompTools::Symbolic::Constraint

  def renderer(arch = :amd64)
    described_class.new(SeccompTools::Explain::QwordFusion.new(arch))
  end

  # Renders a single constraint (no syscall context, so arguments stay generic).
  def render(constraint, sys: nil, arch: :amd64)
    renderer(arch).conjunction([constraint], sys)
  end

  describe 'field names' do
    it 'names the fixed fields and generic argument words' do
      expect(render(c.new(e.data(0), :==, e.imm(1)))).to eq 'sys_number == 0x1'
      expect(render(c.new(e.data(4), :==, e.imm(1)))).to eq 'arch == 0x1'
      expect(render(c.new(e.data(8), :==, e.imm(1)))).to eq 'instruction_pointer == 0x1'
      expect(render(c.new(e.data(16), :==, e.imm(1)))).to eq 'args[0] == 0x1'
      expect(render(c.new(e.data(20), :==, e.imm(1)))).to eq 'args[0] >> 32 == 0x1'
    end

    it 'uses the syscall prototype names when the syscall is known' do
      expect(render(c.new(e.data(16), :==, e.imm(1)), sys: :read)).to eq 'fd == 0x1'
    end

    it 'follows big-endian word order for the high half' do
      # on s390x data[16] is the high half of args[0]
      expect(render(c.new(e.data(16), :==, e.imm(1)), arch: :s390x)).to eq 'args[0] >> 32 == 0x1'
    end
  end

  describe 'operator precedence and clarity parentheses' do
    it 'wraps a bitwise operand of a comparison (== binds tighter than &)' do
      lhs = e.data(16).apply(:&, e.imm(0xff))
      expect(render(c.new(lhs, :==, e.imm(5)))).to eq '(args[0] & 0xff) == 0x5'
    end

    it 'keeps a shift operand of a comparison unwrapped' do
      lhs = e.data(16).apply(:>>, e.imm(4))
      expect(render(c.new(lhs, :==, e.imm(5)))).to eq 'args[0] >> 4 == 0x5'
    end

    it 'wraps mixed operator families for readability' do
      lhs = e.data(16).apply(:&, e.data(24).apply(:+, e.imm(1)))
      expect(render(c.new(lhs, :==, e.imm(5)))).to eq '(args[0] & (args[1] + 0x1)) == 0x5'
    end

    it 'renders jset as a masked bit test' do
      expect(render(c.new(e.data(16), :set, e.imm(0x101)))).to eq '(args[0] & 0x101) != 0'
      expect(render(c.new(e.data(16), :unset, e.imm(0x101)))).to eq '(args[0] & 0x101) == 0'
    end

    it 'renders unary negation' do
      expect(render(c.new(e.data(16).apply(:neg, nil), :==, e.imm(1)))).to eq '-args[0] == 0x1'
    end
  end

  describe 'a Qword fact' do
    it 'names the whole 64-bit field and its value' do
      qword = SeccompTools::Explain::Qword.new(32, :>=, 0x1000) # args[2] = count on read
      expect(renderer.conjunction([qword], :read)).to eq 'count >= 0x1000'
    end
  end

  it 'joins several facts with &&' do
    conds = [c.new(e.data(16), :==, e.imm(1)), c.new(e.data(24), :>, e.imm(2))]
    expect(renderer.conjunction(conds, nil)).to eq 'args[0] == 0x1 && args[1] > 0x2'
  end
end
