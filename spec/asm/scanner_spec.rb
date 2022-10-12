# frozen_string_literal: true

require 'seccomp-tools/asm/scanner'
require 'seccomp-tools/asm/token'
require 'seccomp-tools/const'

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
    it 'goto' do
      s = described_class.new(<<-EOS, :amd64)
      goto whatever_1
      if (A == 123) gOto 1 else GoTo 2
      EOS
      expect(s.scan.count { |t| t.sym == :GOTO }).to be 3
      expect(s.scan.count { |t| t.sym == :GOTO_SYMBOL }).to be 3
    end

    it 'keywords' do
      s = described_class.new(<<-EOS, :amd64)
      if else A X RETurn
      len mem ARGS args_h data sYS_NUMBEr aRch instRUCtion_pointer
      EOS
      expect(s.scan.count { |t| t.sym != :NEWLINE }).to be 13
      expect(s.validate).to be_empty
    end

    it 'actions' do
      s = described_class.new(<<-EOS, :amd64)
        KILL_PROCESS
        KILL_THREAD
        KILL
        TRAP
        ERRNO
        USER_NOTIF
        LOG
        TRACE
        ALLOW
      EOS
      expect(s.scan.count { |t| t.sym == :ACTION }).to be SeccompTools::Const::BPF::ACTION.size
    end

    it 'arches' do
      s = described_class.new(<<-EOS, :amd64)
        ARCH_X86_64
        ARCH_I386
        ARCH_AARCH64
        ARCH_S390X
      EOS
      expect(s.scan.count { |t| t.sym == :ARCH_VAL }).to be SeccompTools::Const::Audit::ARCH.size
    end

    it 'syscalls' do
      syscalls = SeccompTools::Const::Syscall::S390X.keys
      s = described_class.new(syscalls.join(' '), :s390x)
      expect(s.scan.count { |t| t.sym == :SYSCALL }).to be syscalls.size
    end

    it 'accepts arch.syscall' do
      arches = SeccompTools::Syscall::ABI.keys
      s = described_class.new(arches.map { |a| "#{a}.open" }.join(' '), :amd64)
      expect(s.scan.count { |t| t.sym == :SYSCALL }).to be arches.size
    end

    it 'symbols' do
      s = described_class.new(<<-EOS, :amd64)
      abc: 123:
    symbol:
      EOS
      expect(s.scan.count { |t| t.sym == :SYMBOL }).to be 3
    end

    it 'integers' do
      s = described_class.new(<<-EOS, :amd64)
      0 0x123 -1 -2 1337 -0x1337
      EOS
      expect(s.scan.count { |t| t.sym == :HEX_INT || t.sym == :INT }).to be 6
    end

    it 'alu operators' do
      s = described_class.new(<<-EOS, :amd64)
      += -= *= /= |= ^= <<= >>=
      EOS
      expect(s.scan.count { |t| t.sym == :ALU_OP }).to be 8
    end

    it 'compare' do
      s = described_class.new(<<-EOS, :amd64)
      == != >= <= > <
      EOS
      expect(s.scan.count { |t| t.sym == :COMPARE }).to be 6
    end

    it 'marks' do
      s = described_class.new(<<-EOS, :amd64)
      () [] =
      EOS
      expect(s.scan.count { |t| t.sym.is_a?(String) }).to be 5
    end

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
                             SeccompTools::Asm::Token.new(:A, 'A', 1, 6),
                             SeccompTools::Asm::Token.new(:NEWLINE, "\n", 1, 16)
                           ])
    end

    it 'accepts ternary operator' do
      s = described_class.new(<<-EOS, :aarch64)
      A == ARCH_X86_64 ? next : dead
      EOS
      expect(s.scan).to eq([
                             SeccompTools::Asm::Token.new(:A, 'A', 0, 6),
                             SeccompTools::Asm::Token.new(:COMPARE, '==', 0, 8),
                             SeccompTools::Asm::Token.new(:ARCH_VAL, 'ARCH_X86_64', 0, 11),
                             SeccompTools::Asm::Token.new(:GOTO_SYMBOL, 'next', 0, 25),
                             SeccompTools::Asm::Token.new(:GOTO_SYMBOL, 'dead', 0, 32),
                             SeccompTools::Asm::Token.new(:NEWLINE, "\n", 0, 36)
                           ])
    end
  end
end
