# frozen_string_literal: true

require 'seccomp-tools/asm/scanner'
require 'seccomp-tools/asm/token'

describe SeccompTools::Asm::Scanner do
  describe 'validate' do
    it 'valid' do
      expect(described_class.new('', :i386).validate).to be_empty
      s = described_class.new(<<-EOS, :amd64)
      label1: A == write
      EOS
      expect(s.validate).to be_empty
    end

    it 'invalid' do
      # ARM64 only has 'openat' syscall but not 'open'
      s = described_class.new(<<-EOS, :aarch64)
      label1: A = open
      A = openat
      EOS
      expect(s.validate).to eq [
        SeccompTools::Asm::Token.new(:unknown, 'open', 0, 18)
      ]
    end

    it 'error message' do
      s = described_class.new(<<-EOS, :aarch64)
      label1: A = open
      A = openat
      A %%% 1
meow
 two errors
      EOS
      expect { s.validate! }.to raise_error(SeccompTools::UnrecognizedTokenError, <<-EOS)
<inline>:1:19 unknown token "open"
      label1: A = open
                  ^^^^

<inline>:3:9 unknown token "%%%"
      A %%% 1
        ^^^

<inline>:4:1 unknown token "meow"
meow
^^^^

<inline>:5:2 unknown token "two"
 two errors
 ^^^

<inline>:5:6 unknown token "errors"
 two errors
     ^^^^^^
      EOS
    end
  end

  describe 'scan' do
    it 'if expressions' do
      s = described_class.new(<<-EOS, :amd64)
if (A <= write) goto   xyz
  if(A== 0x123 )    goto dead   else goto ok
      EOS
      tokens = s.scan
      tokens.map! { |t| "#{t.line}:#{t.col} #{t.sym}:#{t.str}" }
      expect(tokens).to eq [
        '0:0 IF:if', '0:3 (:(', '0:4 A:A', '0:6 COMPARE:<=', '0:9 SYSCALL:write',
        '0:14 ):)', '0:16 GOTO:goto', '0:23 GOTO_SYMBOL:xyz', "0:26 NEWLINE:\n",

        '1:2 IF:if', '1:4 (:(', '1:5 A:A', '1:6 COMPARE:==', '1:9 HEX_INT:0x123',
        '1:15 ):)', '1:20 GOTO:goto', '1:25 GOTO_SYMBOL:dead', '1:32 ELSE:else',
        '1:37 GOTO:goto', '1:42 GOTO_SYMBOL:ok', "1:44 NEWLINE:\n"
      ]
    end

    it 'keywords' do
      s = described_class.new(<<-EOS, :amd64)
      if else gOtO a_label A X () read write open RETurn 123456789 0x1337
      if(A==ioctl) ][
      sYmBol:
      mem args sys_number arch instruction_pointer
      kill allow errno
      += -= *= /= &= |= ^= <<= >>=
      EOS
      tokens = s.scan
      # 43 tokens + 6 \n
      expect(tokens.size).to be 49
      expect(s.validate).to be_empty
    end

    it 'empty lines' do
      s = described_class.new(<<-EOS, :s390x)
      line0: A = 123


      line3: return A
      EOS
      tokens = s.scan
      expect(tokens).to include(SeccompTools::Asm::Token.new(:RETURN, 'return', 3, 13))
    end

    it 'comments' do
      s = described_class.new(<<-EOS, :aarch64)
      # a comment
      A # return
      EOS
      expect(s.scan).to eq([
                             SeccompTools::Asm::Token.new(:NEWLINE, "\n", 0, 17),
                             SeccompTools::Asm::Token.new(:A, 'A', 1, 6),
                             SeccompTools::Asm::Token.new(:NEWLINE, "\n", 1, 16)
                           ])
    end
  end
end
