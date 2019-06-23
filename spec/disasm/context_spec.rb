# frozen_string_literal: true

require 'seccomp-tools/disasm/context'

describe SeccompTools::Disasm::Context do
  it 'dup' do
    ctx = described_class.new

    nctx = ctx.dup
    nctx.load(:a, rel: :data, val: 0)
    nctx.load(:x, rel: :data, val: 4)
    nctx.store(0, :a) # mem[0] = data[0]
    nctx.store(1, :x) # mem[1] = data[4]

    nnctx = nctx.dup
    nnctx.store(0, :x) # mem[0] = data[4]
    nnctx.load(:x, rel: :mem, val: 2) # x = mem[2]

    expect(ctx.x.val).to be_nil
    expect(ctx[0].data?).to be false
    expect(ctx[0].val).to be 0

    expect(nctx.x.data?).to be true
    expect(nctx.x.val).to be 4
    expect(nctx[0].data?).to be true
    expect(nctx[0].val).to be 0
    expect(nctx[1].val).to be 4

    expect(nnctx.x.data?).to be false
    expect(nnctx.x.val).to be 2
    expect(nnctx[0].val).to be 4
    expect(nnctx[1].val).to be 4
  end

  it 'load' do
    ctx = described_class.new
    ctx.load(:a, rel: :data, val: 4)
    expect(ctx.a.data?).to be true
    expect(ctx.a.val).to be 4

    ctx.load(:a, rel: :mem, val: 8)
    expect(ctx.a.data?).to be false
    expect(ctx.a.val).to be 8

    ctx.load(:x, rel: :imm, val: 16)
    expect(ctx.x.val).to be 16
  end

  it 'store' do
    ctx = described_class.new
    ctx.load(:a, rel: :data, val: 0)
    ctx.store(4, :a)

    ctx.load(:x, rel: :mem, val: 4)
    expect(ctx.x.data?).to be true
    expect(ctx.x.val).to be_zero
  end

  it 'known_data' do
    ctx = described_class.new
    ctx.load(:a, rel: :data, val: 0)
    ctx.eql!(1337)
    expect(ctx.known_data[0]).to be 1337

    ctx.load(:a, rel: :data, val: 4)
    ctx.load(:x, rel: :imm, val: 0x123)
    ctx.eql!(:x)
    expect(ctx.known_data[4]).to be 0x123

    ctx.load(:a, rel: :data, val: 8)
    ctx.load(:x, rel: :data, val: 0)
    ctx.eql!(:x)
    expect(ctx.known_data[8]).to be 1337
  end
end
