require 'seccomp-tools/context'

describe SeccompTools::Context do
  it 'dup' do
    ctx = described_class.new
    nctx = ctx.dup
    nctx.a = :syscall_number
    nctx.x = :arch
    nctx.mem[0] = nctx.a
    nctx.mem[1] = nctx.x
    nnctx = nctx.dup
    nnctx.x = nnctx.mem[0]
    nnctx.mem[0] = nctx.mem[1]

    expect(ctx.x).to be nil
    expect(ctx.mem).to be_empty

    expect(nctx.x).to be :arch
    expect(nctx.mem[0]).to be :syscall_number

    expect(nnctx.x).to be :syscall_number
    expect(nnctx.mem[0]).to be :arch
    expect(nnctx.mem[1]).to be :arch
  end
end
