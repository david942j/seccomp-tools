require 'seccomp-tools/util'

describe SeccompTools::Util do
  it 'supported_archs' do
    expect(described_class.supported_archs).to eq %i(amd64 i386)
  end

  it 'system arch' do
    org = RbConfig::CONFIG['host_cpu']
    RbConfig::CONFIG['host_cpu'] = 'x86_64'
    expect(described_class.system_arch).to be :amd64
    RbConfig::CONFIG['host_cpu'] = 'i386'
    expect(described_class.system_arch).to be :i386
    RbConfig::CONFIG['host_cpu'] = 'aarch64'
    expect(described_class.system_arch).to be :unknown
    RbConfig::CONFIG['host_cpu'] = org
  end

  it 'colorize' do
    described_class.stub(:colorize_enabled?) { true }
    expect(described_class.colorize('meow', t: :syscall)).to eq "\e[38;5;120mmeow\e[0m"
  end
end
