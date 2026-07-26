# encoding: ascii-8bit
# frozen_string_literal: true

require 'json'
require 'stringio'

require 'seccomp-tools/cli/audit'
require 'seccomp-tools/util'

describe SeccompTools::CLI::Audit do
  before { SeccompTools::Util.disable_color! }

  def data(name)
    File.join(__dir__, '..', 'data', name)
  end

  def capture(argv)
    io = StringIO.new
    orig = $stdout
    $stdout = io
    described_class.new(argv).handle
    io.string
  ensure
    $stdout = orig
  end

  it 'prints a human report' do
    out = capture([data('twctf-2016-diary.bpf'), '-a', 'amd64'])
    expect(out).to include('Seccomp audit of', '[HIGH] Architecture is never validated')
  end

  it 'reports a clean allowlist as having no weaknesses' do
    out = capture([data('libseccomp.bpf'), '-a', 'amd64'])
    expect(out).to include('No weaknesses found')
  end

  it 'emits a valid JSON document with --format json' do
    doc = JSON.parse(capture([data('gctf-2019-quals-caas.bpf'), '-a', 'amd64', '-f', 'json']))
    expect(doc['stacked_filters']).to eq 1
    report = doc['reports'].first
    expect(report['arches']).to eq ['amd64']
    expect(report['findings'].map { |f| f['id'] }).to include('dangerous-allow')
    socket = report['findings'].find { |f| f['syscalls'] == ['socket'] }
    expect(socket['severity']).to eq 'medium'
    expect(socket['condition']).to include('== 0x2')
  end

  it 'reads a raw filter from stdin' do
    allow($stdin).to receive(:read).and_return(File.binread(data('twctf-2016-diary.bpf')))
    out = capture(['-', '-a', 'amd64'])
    expect(out).to include('Seccomp audit of <STDIN>', 'x32 ABI is not guarded')
  end

  it 'warns about and separately labels several stacked filters' do
    f0 = File.binread(data('twctf-2016-diary.bpf'))
    f1 = File.binread(data('libseccomp.bpf'))
    stub_const('SeccompTools::Dumper::SUPPORTED', true)
    allow(SeccompTools::Dumper).to receive(:dump) do |*, **, &blk|
      [blk.call(f0, :amd64), blk.call(f1, :amd64)]
    end
    out = capture(['-c', './x', '-a', 'amd64', '-l', '2', '-t', '1.5'])
    expect(out).to include('filters are installed', '(filter #0)', '(filter #1)')
  end

  it 'audits filters dumped from a running process via --pid' do
    stub_const('SeccompTools::Dumper::SUPPORTED', true)
    allow(SeccompTools::Dumper).to receive(:dump_by_pid) do |*, &blk|
      [blk.call(File.binread(data('twctf-2016-diary.bpf')), nil)]
    end
    out = capture(['-p', '1234', '-a', 'amd64'])
    expect(out).to include('x32 ABI is not guarded')
  end
end
