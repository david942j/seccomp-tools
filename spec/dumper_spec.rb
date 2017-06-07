# encoding: ascii-8bit

require 'seccomp-tools/dumper'

describe SeccompTools::Dumper do
  before do
    @binpath = File.join(__dir__, 'binary')
  end
  describe 'amd64' do
    context 'diary' do
      before do
        @diary = File.join(@binpath, 'twctf-2016-diary')
        @bpf = " \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01;\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x018\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x019\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01:\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01U\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01B\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F" # rubocop:disable Metrics/LineLength
      end

      it 'default' do
        output = described_class.dump(@diary)
        expect(output.size).to be 1
        expect(output.first).to eq @bpf
      end

      it 'block' do
        expect(described_class.dump(@diary) { |c| c == @bpf }).to eq [true]
      end
    end

    context 'clone_two_seccomp' do
      it 'check' do
        @bin = File.join(@binpath, 'clone_two_seccomp')
        expect(described_class.dump(@bin, limit: -1).size).to be 2
      end
    end

    context 'no seccomp' do
      it { expect(described_class.dump('ls', '-lh')).to be_empty }
    end

    context 'no such binary' do
      it { expect(described_class.dump('this_is_not_exist')).to eq [] }
    end
  end

  describe 'i386' do
    context 'amigo' do
      it 'normal' do
        bin = File.join(@binpath, 'CONFidence-2017-amigo')
        bpf = IO.binread(File.join(__dir__, 'data', 'CONFidence-2017-amigo.bpf'))
        got = described_class.dump(bin).first
        # there's pid inside seccomp rules.. ignore it
        expect(got.size).to be bpf.size
        expect(got[0, 0x1ec]).to eq bpf[0, 0x1ec]
        expect(got[0x1ee..-1]).to eq bpf[0x1ee..-1]
      end
    end
  end
end
