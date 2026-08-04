# frozen_string_literal: true

require 'open-uri'

require 'seccomp-tools/util'

# Regenerate the syscall-number tables under lib/seccomp-tools/consts/sys_nr/ by fetching the kernel
# syscall tables straight from the upstream Linux source, for every architecture seccomp-tools
# supports. Nothing is vendored; the tables are pulled from a pinned tag at run time.
#
#   $ bundle exec rake sys_nr                    # uses the pinned LINUX_VERSION below
#   $ LINUX_VERSION=v8.0 bundle exec rake sys_nr # refresh to another release
#
# The merge is additive: existing name => number entries are kept verbatim (so hand-curated aliases
# such as `getdents` for `getdents64` survive), and only syscalls whose number is not already present
# are appended. Numbers are a stable kernel ABI and never change, so rerunning on the same tag is a
# no-op.
module SysNrGen
  ROOT = 'lib/seccomp-tools/consts/sys_nr'
  # Pinned by default; a stable release, not an -rc (whose numbers can still move). Overridable via env.
  LINUX_VERSION = ENV.fetch('LINUX_VERSION', 'v7.1')
  BASE = "https://raw.githubusercontent.com/torvalds/linux/#{LINUX_VERSION}".freeze

  # For each architecture: the upstream syscall table and the ABIs that arch is built from. The ABI
  # sets mirror the kernel's own per-arch syscalltbl invocation. aarch64/riscv64 share the generic
  # scripts/syscall.tbl; x86 and s390 keep their own. A new supported arch adds an entry here.
  SOURCES = {
    amd64: { path: 'arch/x86/entry/syscalls/syscall_64.tbl', abis: %w[common 64], x32: true },
    i386: { path: 'arch/x86/entry/syscalls/syscall_32.tbl', abis: %w[i386] },
    aarch64: { path: 'scripts/syscall.tbl', abis: %w[common 64 renameat rlimit memfd_secret] },
    riscv64: { path: 'scripts/syscall.tbl', abis: %w[common 64 rlimit memfd_secret riscv] },
    s390x: { path: 'arch/s390/kernel/syscalls/syscall.tbl', abis: %w[common] }
  }.freeze

  module_function

  # Fetches an upstream file, memoized so the shared generic table is pulled only once.
  # @return [String]
  def fetch(path)
    (@cache ||= {})[path] ||= URI.parse("#{BASE}/#{path}").open(&:read)
  end

  # Parses a kernel syscall .tbl, keeping rows whose ABI the arch wants.
  # @return [Hash{Symbol=>Integer}] Syscall name to number, first occurrence winning.
  def parse(content, abis)
    content.lines.each_with_object({}) do |line, table|
      next if line =~ /\A\s*#/ || line.strip.empty?

      nr, abi, name, = line.split(/\s+/)
      next unless name && abis.include?(abi)

      table[name.to_sym] ||= nr.to_i
    end
  end

  # The architecture's current table, without the +x32_+ aliases the +.tap+ block synthesizes.
  # @return [Hash{Symbol=>Integer}]
  def current(arch)
    eval(File.read(File.join(ROOT, "#{arch}.rb"))).reject { |name, _| name.to_s.start_with?('x32_') } # rubocop:disable Security/Eval
  end

  # Renders +table+ (name => number) as the Ruby source of a sys_nr file.
  def render(table, x32:)
    body = table.sort_by { |_, nr| nr }.map { |name, nr| "  #{name}: #{nr}" }.join(",\n")
    out = +"# frozen_string_literal: true\n\n"
    out << "# Denote a x32 syscall.\nX32_MODE_BIT = 0x40000000\n" if x32
    out << "{\n#{body}\n}"
    out << ".tap { |h| h.keys.each { |k| h[:\"x32_\#{k}\"] = h[k] | X32_MODE_BIT } }" if x32
    "#{out}\n"
  end
end

desc 'Regenerate lib/seccomp-tools/consts/sys_nr/ from the upstream Linux syscall tables'
task :sys_nr do
  puts "Fetching syscall tables from torvalds/linux #{SysNrGen::LINUX_VERSION}"
  SeccompTools::Util.supported_archs.each do |arch|
    cfg = SysNrGen::SOURCES.fetch(arch) { raise "no syscall-table source configured for #{arch}" }
    old = SysNrGen.current(arch)
    used = old.values
    tbl = SysNrGen.parse(SysNrGen.fetch(cfg[:path]), cfg[:abis])
    merged = old.merge(tbl.reject { |_, nr| used.include?(nr) })
    File.write(File.join(SysNrGen::ROOT, "#{arch}.rb"), SysNrGen.render(merged, x32: cfg[:x32]))
    puts "  #{arch}: #{merged.size} native syscalls (max #{merged.values.max})"
  end
end
