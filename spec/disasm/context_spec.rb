require 'seccomp-tools/disasm/context'

describe SeccompTools::Disasm::Context do
  it 'dup' do
    ctx = described_class.new
    nctx = ctx.dup
    nctx[:a] = 0
    nctx[:x] = 4
    nctx[0] = nctx.a
    nctx[1] = nctx.x
    nnctx = nctx.dup
    nnctx[:x] = nnctx[0]
    nnctx[0] = nctx[1]

    expect(ctx.x).to be_nil
    expect(ctx[0]).to be_nil

    expect(nctx.x).to be 4
    expect(nctx[0]).to be 0

    expect(nnctx.x).to be 0
    expect(nnctx[0]).to be 4
    expect(nnctx[1]).to be 4
  end
end
