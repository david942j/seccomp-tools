require 'securerandom'

require 'seccomp-tools/cli/disasm'
require 'seccomp-tools/disasm'

describe SeccompTools::CLI::Disasm do
  before do
    @bpf = File.join(__dir__, '..', 'data', 'twctf-2016-diary.bpf')
  end

  it 'normal' do
    expect { described_class.new([@bpf]).handle }.to output(SeccompTools::Disasm.disasm(IO.binread(@bpf))).to_stdout
  end

  it 'output to file' do
    tmp = File.join('/tmp', SecureRandom.hex)
    described_class.new([@bpf, '-o', tmp]).handle
    content = IO.binread(tmp)
    FileUtils.rm(tmp)
    expect(content).not_to be_empty
  end
end
