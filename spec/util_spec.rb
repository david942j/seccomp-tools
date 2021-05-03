# frozen_string_literal: true

require 'seccomp-tools/util'

describe SeccompTools::Util do
  it 'supported_archs' do
    expect(described_class.supported_archs).to eq %i(aarch64 amd64 i386 s390x)
  end

  it 'system arch' do
    org = RbConfig::CONFIG['host_cpu']
    RbConfig::CONFIG['host_cpu'] = 'x86_64'
    expect(described_class.system_arch).to be :amd64
    RbConfig::CONFIG['host_cpu'] = 'i386'
    expect(described_class.system_arch).to be :i386
    RbConfig::CONFIG['host_cpu'] = 'aarch64'
    expect(described_class.system_arch).to be :aarch64
    RbConfig::CONFIG['host_cpu'] = 's390x'
    expect(described_class.system_arch).to be :s390x
    RbConfig::CONFIG['host_cpu'] = 'fake'
    expect(described_class.system_arch).to be :unknown
    RbConfig::CONFIG['host_cpu'] = org
  end

  it 'colorize' do
    allow(described_class).to receive(:colorize_enabled?).and_return(true)
    expect(described_class.colorize('meow', t: :syscall)).to eq "\e[38;5;120mmeow\e[0m"

    described_class.disable_color!
    expect(described_class.instance_variable_get(:@disable_color)).to be true
    described_class.enable_color!
    expect(described_class.instance_variable_get(:@disable_color)).to be false
  end
end
