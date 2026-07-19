# encoding: ascii-8bit
# frozen_string_literal: true

require 'seccomp-tools/dumper'
require 'seccomp-tools/util'

describe SeccompTools::Dumper do
  describe 'amd64' do
    before do
      skip_unless_amd64
    end

    context 'diary' do
      before do
        @diary = bin_of('twctf-2016-diary')
        @bpf = " \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01;\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x018\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x019\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01:\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01U\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01B\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F" # rubocop:disable Layout/LineLength
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
        bin = bin_of('clone_two_seccomp')
        expect(described_class.dump(bin, limit: -1).size).to be 2
      end
    end

    context '0ctf-quals-2018-blackhole' do
      it 'check' do
        # this binary uses syscall +seccomp+ instead of +prctl+
        bin = bin_of('syscall_seccomp')
        expect(described_class.dump(bin).size).to be 1
      end
    end

    context 'strict mode' do
      before do
        # equivalent filter synthesized for SECCOMP_MODE_STRICT, see Syscall.strict_bpf
        @strict_bpf = " \x00\x00\x00\x00\x00\x00\x00\x15\x00\x04\x00\x00\x00\x00\x00\x15\x00\x03\x00\x01\x00\x00\x00\x15\x00\x02\x00<\x00\x00\x00\x15\x00\x01\x00\x0F\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F" # rubocop:disable Layout/LineLength
      end

      it 'prctl' do
        output = described_class.dump(bin_of('strict_prctl'))
        expect(output.size).to be 1
        expect(output.first).to eq @strict_bpf
      end

      it 'seccomp' do
        output = described_class.dump(bin_of('strict_seccomp'))
        expect(output.size).to be 1
        expect(output.first).to eq @strict_bpf
      end
    end

    context 'no seccomp' do
      it { expect(described_class.dump('ls >/dev/null')).to be_empty }
    end

    context 'timeout' do
      it 'kills the process when timeout is reached' do
        start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        expect(described_class.dump('sleep', '1d', timeout: 1)).to be_empty
        expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - start).to be < 10
      end

      it 'returns the filters dumped before the timeout' do
        # pipe from sleep so the binary blocks on stdin until the timeout fires
        output = described_class.dump("sleep 1d | #{bin_of('two_filters')}", limit: -1, timeout: 5)
        expect(output.size).to be 2
      end
    end

    context 'no such binary' do
      it do
        allow(SeccompTools::Logger).to receive(:error)
        expect(described_class.dump('this_is_not_exist')).to be_empty
      end
    end
  end

  describe 'i386' do
    before do
      skip_unless_x86
    end

    context 'amigo' do
      it 'normal' do
        bin = bin_of('CONFidence-2017-amigo')
        bpf = File.binread(File.join(__dir__, 'data', 'CONFidence-2017-amigo.bpf'))
        got = described_class.dump(bin).first
        # there's pid inside seccomp rules.. ignore it
        expect(got.size).to be bpf.size
        expect(got[0, 0x1ec]).to eq bpf[0, 0x1ec]
        expect(got[0x1f0..]).to eq bpf[0x1f0..]
      end
    end
  end

  describe 'by pid' do
    context 'two filters' do
      let(:bin) { bin_of('two_filters') }

      let(:popen) do
        lambda do |&block|
          popen2(bin) do |i, o, pid|
            o.gets # seccomp installed
            block.call(pid)
          ensure
            i.puts
          end
        end
      end

      it 'test limits' do
        skip_unless_amd64
        skip_unless_root

        output = described_class.dump(bin, limit: 2)
        popen.call do |pid|
          expect(described_class.dump_by_pid(pid, 1)).to eq [output.first]
          expect(described_class.dump_by_pid(pid, 2)).to eq output
          expect(described_class.dump_by_pid(pid, -1)).to eq output
        end
      end
    end
  end

  it 'should output warning and exit(1)' do
    allow(SeccompTools::Ptrace).to receive(:traceme_and_stop)
    expect { described_class.__send__(:handle_child, 'no_such_binary') }
      .to terminate.with_code(1).and output("[ERROR] Failed to execute no_such_binary\n").to_stdout
  end
end
