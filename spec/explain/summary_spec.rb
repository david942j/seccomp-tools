# frozen_string_literal: true

require 'seccomp-tools/explain/summary'
require 'seccomp-tools/symbolic/executor'
require 'seccomp-tools/util'

# Full-filter rendering is covered by the integration cases in spec/explain_spec.rb; these tests
# drive Summary directly with hand-built leaves for the cases a whole filter cannot easily produce.
describe SeccompTools::Explain::Summary do
  before { SeccompTools::Util.disable_color! }

  def leaf(ret_val, path: [])
    SeccompTools::Symbolic::Executor::Leaf.new(path, SeccompTools::Symbolic::Expr.imm(ret_val), 0)
  end

  it 'prints the source header above the sections, and a truncation warning when asked' do
    out = described_class.new([leaf(0x7fff0000)], arch: :amd64, source: 'a.bpf').to_s
    expect(out).to start_with("Seccomp policy for a.bpf\n\nArchitecture: amd64\n")
    expect(described_class.new([], arch: :amd64, truncated: true).to_s).to include('analysis truncated')
  end

  it 'notes when a filter runs off the end without returning' do
    expect(described_class.new([], arch: :amd64).to_s).to include('no return reached')
  end

  it 'labels an unrecognized action bucket the way the kernel treats it' do
    expect(described_class.new([leaf(0x12345678)], arch: :amd64).to_s)
      .to include('KILL_PROCESS (unknown action 0x12345678):')
  end

  it 'names a pinned syscall numerically when the arch has no syscall table' do
    # a library caller may pass any arch; naming falls back to the number instead of crashing
    e = SeccompTools::Symbolic::Expr
    path = [SeccompTools::Symbolic::Constraint.new(e.data(0), :==, e.imm(5))]
    out = described_class.new([leaf(0x7fff0000, path:), leaf(0)], arch: :nonesuch).to_s
    expect(out).to include('0x5')
  end

  it 'shows the whole 64-bit value when both argument halves are pinned' do
    e = SeccompTools::Symbolic::Expr
    c = SeccompTools::Symbolic::Constraint
    path = [c.new(e.data(0), :==, e.imm(59)),          # execve
            c.new(e.data(20), :==, e.imm(0x7ffe)),     # args[0] high half
            c.new(e.data(16), :==, e.imm(0xa12f7d0e))] # args[0] low half
    leaves = [leaf(0x7fff0000, path:), leaf(0)]        # the second is the catch-all default (KILL)
    expect(described_class.new(leaves, arch: :amd64).to_s)
      .to include('execve when filename == 0x7ffea12f7d0e')
  end
end
