# frozen_string_literal: true

require 'seccomp-tools/cli/cli'

describe SeccompTools::CLI::Completion do
  def completions_dir
    File.join(__dir__, '..', '..', 'completions')
  end

  it 'prints the bash script' do
    expected = File.read(File.join(completions_dir, 'seccomp-tools.bash'))
    expect { described_class.new(%w[bash]).handle }.to output(expected).to_stdout
  end

  it 'prints the zsh script' do
    expected = File.read(File.join(completions_dir, '_seccomp-tools'))
    expect { described_class.new(%w[zsh]).handle }.to output(expected).to_stdout
  end

  it 'prints the fish script' do
    expected = File.read(File.join(completions_dir, 'seccomp-tools.fish'))
    expect { described_class.new(%w[fish]).handle }.to output(expected).to_stdout
  end

  it 'shows usage when no shell is given' do
    expect { described_class.new([]).handle }.to output(/Usage: seccomp-tools completion <bash\|zsh\|fish>/).to_stdout
  end

  it 'shows usage for an unsupported shell' do
    expect { described_class.new(%w[powershell]).handle }
      .to output(/Usage: seccomp-tools completion <bash\|zsh\|fish>/).to_stdout
  end
end
