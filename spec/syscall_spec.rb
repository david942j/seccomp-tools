# frozen_string_literal: true

require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/syscall'

describe SeccompTools::Syscall do
  describe '.strict_bpf' do
    it 'amd64' do
      output = SeccompTools::Disasm.disasm(described_class.strict_bpf(:amd64), arch: :amd64, display_bpf: false)
      expect(output).to eq <<-EOS
0000: A = sys_number
0001: if (A == read) goto 0006
0002: if (A == write) goto 0006
0003: if (A == exit) goto 0006
0004: if (A == rt_sigreturn) goto 0006
0005: return KILL
0006: return ALLOW
      EOS
    end

    it 'uses sigreturn on architectures that have it' do
      output = SeccompTools::Disasm.disasm(described_class.strict_bpf(:i386), arch: :i386, display_bpf: false)
      expect(output).to eq <<-EOS
0000: A = sys_number
0001: if (A == read) goto 0006
0002: if (A == write) goto 0006
0003: if (A == exit) goto 0006
0004: if (A == sigreturn) goto 0006
0005: return KILL
0006: return ALLOW
      EOS
    end
  end
end
