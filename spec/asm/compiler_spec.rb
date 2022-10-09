# frozen_string_literal: true

require 'seccomp-tools/asm/compiler'
require 'seccomp-tools/error'

describe SeccompTools::Asm::Compiler do
  before(:all) do
    @get_bpf = lambda do |line, arch: :amd64|
      described_class.new(line, nil, arch).compile!.first.decompile
    end
  end

  describe 'ld' do
    it 'misc' do
      expect(@get_bpf['A = X']).to eq 'A = X'
      expect(@get_bpf['X = A']).to eq 'X = A'
      expect(@get_bpf['X=A']).to eq 'X = A'
    end

    it 'imm' do
      expect(@get_bpf['A = 123']).to eq 'A = 123'
      expect(@get_bpf['A = nanosleep']).to eq 'A = 35'
      expect(@get_bpf['X = nanosleep']).to eq 'X = 35'
      expect(@get_bpf['A = nanosleep', arch: :i386]).to eq 'A = 162'

      expect { @get_bpf['A = not_exists_syscall'] }.to raise_error(SeccompTools::UnrecognizedTokenError)
    end

    it 'mem' do
      expect(@get_bpf['A = mem[0]']).to eq 'A = mem[0]'
      expect(@get_bpf['X = mem[1]']).to eq 'X = mem[1]'
    end

    it 'data' do
      expect(@get_bpf['A = data[0]']).to eq 'A = sys_number'
      expect { @get_bpf['A = data[1]'] }.to raise_error(SeccompTools::ParseError, <<-EOS)
<inline>:1:10 index of data[] must be a multiple of 4 and less than 64, got 1
A = data[1]
         ^
      EOS
      expect(@get_bpf['A = sys_number']).to eq 'A = sys_number'
      expect(@get_bpf['A = arch']).to eq 'A = arch'
      expect(@get_bpf['A = len']).to eq 'A = 64'
      expect(@get_bpf['A = args[0]']).to eq 'A = args[0]'
      expect(@get_bpf['A = args[1]']).to eq 'A = args[1]'
      expect(@get_bpf['A = args_h[0]']).to eq 'A = args[0] >> 32'
      expect(@get_bpf['A = args_h[1]']).to eq 'A = args[1] >> 32'
    end

    it 'accepts right shift' do
      expect(@get_bpf['A = instruction_pointer >> 32']).to eq 'A = instruction_pointer >> 32'
      expect(@get_bpf['A = args[0] >> 32']).to eq 'A = args[0] >> 32'
    end
  end

  describe 'condtional' do
    it 'accepts ternary' do
      compiler = described_class.new(<<-EOS, nil, :amd64)
0000: A = sys_number
0001: A == read ? ok : dead
0002: A != read ? ok : 2
0003: A <= 0x1337 ? ok : next
0004: A < 1337 ? ok : dead
0005: A >= read ? ok : dead
ok:
return ALLOW
dead:
return KILL
      EOS
      expect(compiler.compile!.map(&:decompile).join("\n")).to eq <<-EOS.strip
A = sys_number
if (A == 0) goto 0006 else goto 0007
if (A == 0) goto 0005 else goto 0006
if (A <= 4919) goto 0006
if (A >= 1337) goto 0007 else goto 0006
if (A < 0) goto 0007
return ALLOW
return KILL
      EOS
    end

    it 'accepts if-else' do
      compiler = described_class.new(<<-EOS, nil, :amd64)
0000: A = sys_number
0001: if (A == 0) goto 0006 else goto 0007
0002: if (A & X) goto 0005 else goto 0006
0003: if (A != 4919) goto 0006
0004: if (A & 1337) goto 0007 else goto 0006
0005: if (A > 0) goto 0007
0006: return ALLOW
0007: return KILL
      EOS
      expect(compiler.compile!.map(&:decompile).join("\n")).to eq <<-EOS.strip
A = sys_number
if (A == 0) goto 0006 else goto 0007
if (A & X) goto 0005 else goto 0006
if (A != 4919) goto 0006
if (A & 1337) goto 0007 else goto 0006
if (A > 0) goto 0007
return ALLOW
return KILL
      EOS
    end
  end

  it 'ret' do
    expect(@get_bpf['return ERRNO(3)']).to eq 'return ERRNO(3)'
    expect(@get_bpf['return ALLOW']).to eq 'return ALLOW'
    expect(@get_bpf['return KILL']).to eq 'return KILL'
    expect(@get_bpf['return A']).to eq 'return A'
    expect { @get_bpf['return QQ'] }.to raise_error(SeccompTools::UnrecognizedTokenError, <<-EOS)
<inline>:1:8 unknown token "QQ"
return QQ
       ^^
    EOS
  end

  it 'alu' do
    expect(@get_bpf['A += 0x31337']).to eq 'A += 0x31337'
    expect(@get_bpf['A &= read']).to eq 'A &= 0x0'
    expect(@get_bpf['A ^= X']).to eq 'A ^= X'
    expect(@get_bpf['A = -A']).to eq 'A = -A'
  end

  describe 'jump' do
    it 'raises on backward jump' do
      compiler = described_class.new(<<-EOS, nil, :amd64)
    A = 0
loop:
    A += 1
    A <= 10 ? loop : next
      EOS
      expect { compiler.compile! }.to raise_error(SeccompTools::BackwardJumpError, <<-EOS)
<inline>:4:15 Does not support backward jumping to 'loop'
    A <= 10 ? loop : next
              ^^^^
      EOS
    end

    it 'raises on undefined label' do
      compiler = described_class.new(<<-EOS, nil, :amd64)
# a comment for good measures
A = sys_number

A == open  ? alow : next # oops misspelled a label
A == close ? allow : next
A == read  ? allow : next
A == write ? allow : next
A == exit  ? allow : next
A == exit_group ? allow : next
return KILL # default action

allow:
return ALLOW
      EOS
      expect { compiler.compile! }.to raise_error(SeccompTools::UndefinedLabelError, <<-EOS)
<inline>:4:14 Cannot find label 'alow'
A == open  ? alow : next # oops misspelled a label
             ^^^^
      EOS
    end

    it 'accepts jump without conditions' do
      compiler = described_class.new(<<-EOS, nil, :amd64)
goto next
jump jump_a
A = X

jump_a:
A = sys_number
jmp jump_b
X = A

# a comment
jump_b:
A = arch
      EOS

      expect(compiler.compile!.map(&:decompile).join("\n")).to eq <<-EOS.strip
goto 0001
goto 0003
A = X
A = sys_number
goto 0006
X = A
A = arch
      EOS
    end
  end

  describe 'label' do
    it 'accepts multiple labels' do
      compiler = described_class.new(<<-EOS, nil, :amd64)
      goto label
      goto lll
      goto Label
      A = X
lll: Label: label:
      X = A
      EOS

      expect(compiler.compile!.map(&:decompile).join("\n")).to eq <<-EOS.strip
goto 0004
goto 0004
goto 0004
A = X
X = A
      EOS
    end

    it 'raises on duplicated labels' do
      compiler = described_class.new(<<-EOS, nil, :amd64)
label: A = X
       X = A
label: A = 123
      EOS

      expect { compiler.compile! }.to raise_error(SeccompTools::DuplicateLabelError, <<-EOS)
<inline>:3:1 duplicate label 'label'
label: A = 123
^^^^^
<inline>:1:1 previously defined here
label: A = X
^^^^^
      EOS
    end
  end
end
