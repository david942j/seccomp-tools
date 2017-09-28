require 'securerandom'

require 'seccomp-tools/cli/asm'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Asm do
  before do
    @asm = File.join(__dir__, '..', 'data', 'libseccomp.asm')
    @bpf = IO.binread(File.join(__dir__, '..', 'data', 'libseccomp.bpf'))
    SeccompTools::Util.disable_color!
  end

  it 'format' do
    expect { described_class.new([@asm]).handle }.to output(@bpf.inspect + "\n").to_stdout
    expect { described_class.new([@asm, '-f', 'carray']).handle }.to output(<<-EOS).to_stdout
unsigned char bpf[] = {#{@bpf.bytes.join(',')}};
    EOS
  end

  it 'ofile' do
    tmp = File.join('/tmp', SecureRandom.hex)
    described_class.new([@asm, '-o', tmp, '-f', 'raw']).handle
    content = IO.binread(tmp)
    FileUtils.rm(tmp)
    expect(content).to eq @bpf
  end
end
