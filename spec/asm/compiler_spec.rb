# frozen_string_literal: true

require 'seccomp-tools/asm/compiler'

describe SeccompTools::Asm::Compiler do
  before(:all) do
    @get_bpf = lambda do |line, arch: :amd64|
      compiler = described_class.new(arch)
      compiler.process(line)
      compiler.compile!.first.decompile
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

      expect { @get_bpf['A = not_exists_syscall'] }.to raise_error(ArgumentError)
    end

    it 'mem' do
      expect(@get_bpf['A = mem[0]']).to eq 'A = mem[0]'
      expect(@get_bpf['X = mem[1]']).to eq 'X = mem[1]'
    end

    it 'data' do
      expect(@get_bpf['A = data[0]']).to eq 'A = sys_number'
      expect { @get_bpf['A = data[1]'] }.to raise_error(ArgumentError, <<-EOS.strip)
Invalid instruction at line 1: "A = data[1]"
Error: Index of data[] must be a multiple of 4
      EOS
      expect(@get_bpf['A = sys_number']).to eq 'A = sys_number'
      expect(@get_bpf['A = arch']).to eq 'A = arch'
      expect(@get_bpf['A = len']).to eq 'A = 64'
      expect(@get_bpf['A = args[0]']).to eq 'A = args[0]'
      expect(@get_bpf['A = args[1]']).to eq 'A = args[1]'
      expect(@get_bpf['A = args_h[0]']).to eq 'A = args[0] >> 32'
      expect(@get_bpf['A = args_h[1]']).to eq 'A = args[1] >> 32'
    end
  end

  it 'cmp' do
    compiler = described_class.new(:amd64)
    <<-EOS.lines.each { |l| compiler.process(l) }
A = sys_number
A == read ? ok : dead
A != read ? ok : 2
A <= 0x1337 ? ok : next
A < 1337 ? ok : dead
A >= read ? ok : dead
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

  it 'ret' do
    expect(@get_bpf['return ERRNO(3)']).to eq 'return ERRNO(3)'
    expect(@get_bpf['return ALLOW']).to eq 'return ALLOW'
    expect(@get_bpf['return KILL']).to eq 'return KILL'
    expect(@get_bpf['return A']).to eq 'return A'
    expect { @get_bpf['return QQ'] }.to raise_error(<<-EOS)
Invalid instruction at line 1: "return QQ"
Error: Invalid return type: "QQ".
    EOS
  end

  it 'alu' do
    expect(@get_bpf['A += 0x31337']).to eq 'A += 0x31337'
    expect(@get_bpf['A &= read']).to eq 'A &= 0x0'
    expect(@get_bpf['A ^= X']).to eq 'A ^= X'
  end

  it 'back_jump' do
    compiler = described_class.new(:amd64)

    <<-EOS.lines.each { |l| compiler.process(l) }
A = 0
loop:
A += 1
A <= 10 ? loop : next
    EOS
    expect { compiler.compile! }.to raise_error(ArgumentError, <<-EOS.strip)
Invalid instruction at line 4: "A <= 10 ? loop : next"
Error: Does not support backward jumping to "loop"
    EOS
  end

  it 'bad_jump' do
    compiler = described_class.new(:amd64)

    <<-EOS.lines.each { |l| compiler.process(l) }
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
    expect { compiler.compile! }.to raise_error(ArgumentError, <<-EOS.strip)
Invalid instruction at line 4: "A == open  ? alow : next # oops misspelled a label"
Error: Undefined label "alow"
    EOS
  end

  it 'abs_jump' do
    compiler = described_class.new(:amd64)

    <<-EOS.lines.each { |l| compiler.process(l) }
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

  it 'invalid' do
    msg = 'Invalid instruction at line 5: "Pusheen # meow"'
    compiler = described_class.new(:amd64)
    expect { <<-EOS.lines.each { |l| compiler.process(l) } }.to raise_error(ArgumentError, msg)
# comment
A = sys_number
ok:
return ALLOW
Pusheen # meow
return KILL
    EOS
  end

  it 'invalid2' do
    msg = <<-EOS.strip
Invalid instruction at line 4: "jumping around"
Error: Invalid jump alias: "jumping around"
    EOS

    compiler = described_class.new(:amd64)
    expect { <<-EOS.lines.each { |l| compiler.process(l) } }.to raise_error(ArgumentError, msg)
# comment
A = sys_number
X = A
jumping around
return ALLOW
    EOS

    compiler.compile!
  end
end
