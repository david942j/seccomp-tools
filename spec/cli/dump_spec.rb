# encoding: ascii-8bit

require 'seccomp-tools/cli/cli'

describe SeccompTools::CLI::Dump do
  before do
    @binpath = File.join(__dir__, 'binary')
  end

  it 'exec not present' do
    expect { SeccompTools::CLI.work(['dump']) }.to raise_error(ArgumentError, 'Option -e not present')
  end

  it 'normal' do
    SeccompTools::CLI.work(['dump', '-e', "'#{File.join(@binpath, 'twctf-2016-diary')}'"])
  end
end
