# frozen_string_literal: true

# Generates the strict_prctl and strict_seccomp fixtures: minimal static amd64 ELFs that enable
# SECCOMP_MODE_STRICT and then exit. These can't be produced by the Makefile on a non-amd64 host,
# so the ELFs are built byte-by-byte here instead; run `ruby gen_strict_mode.rb` to regenerate.
#
# Needs the elftools gem (not a dependency of seccomp-tools): gem install elftools
#
# The machine code is the hand-assembled equivalent of:
#
#   int main() {
#     prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);      // or seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL)
#     syscall(SYS_exit, 0);                            // exit_group is not allowed in strict mode
#   }

require 'elftools'

BASE = 0x400000
# ELF header (64) + one program header (56)
CODE_OFFSET = 0x78

# mov edi, 22 ; PR_SET_SECCOMP
# mov esi, 1  ; SECCOMP_MODE_STRICT
# mov eax, 157; SYS_prctl
# syscall
# xor edi, edi
# mov eax, 60 ; SYS_exit
# syscall
STRICT_PRCTL = "\xbf\x16\x00\x00\x00" \
               "\xbe\x01\x00\x00\x00" \
               "\xb8\x9d\x00\x00\x00" \
               "\x0f\x05" \
               "\x31\xff" \
               "\xb8\x3c\x00\x00\x00" \
               "\x0f\x05".b

# xor edi, edi ; SECCOMP_SET_MODE_STRICT
# xor esi, esi
# xor edx, edx
# mov eax, 317 ; SYS_seccomp
# syscall
# xor edi, edi
# mov eax, 60  ; SYS_exit
# syscall
STRICT_SECCOMP = "\x31\xff" \
                 "\x31\xf6" \
                 "\x31\xd2" \
                 "\xb8\x3d\x01\x00\x00" \
                 "\x0f\x05" \
                 "\x31\xff" \
                 "\xb8\x3c\x00\x00\x00" \
                 "\x0f\x05".b

def build_elf(code)
  size = CODE_OFFSET + code.size

  ehdr = ELFTools::Structs::ELF_Ehdr.new(endian: :little)
  ehdr.elf_class = 64
  ehdr.e_ident.magic = ELFTools::Constants::ELFMAG
  ehdr.e_ident.ei_class = 2 # ELFCLASS64
  ehdr.e_ident.ei_data = 1 # ELFDATA2LSB
  ehdr.e_ident.ei_version = 1
  ehdr.e_ident.ei_padding = "\x00" * 7 # not defaulted; without this the header serializes short
  ehdr.e_type = 2 # ET_EXEC
  ehdr.e_machine = 62 # EM_X86_64
  ehdr.e_version = 1
  ehdr.e_entry = BASE + CODE_OFFSET
  ehdr.e_phoff = ehdr.num_bytes
  ehdr.e_ehsize = ehdr.num_bytes
  ehdr.e_phentsize = ELFTools::Structs::ELF_Phdr[64].new(endian: :little).num_bytes
  ehdr.e_phnum = 1

  phdr = ELFTools::Structs::ELF_Phdr[64].new(endian: :little)
  phdr.p_type = 1 # PT_LOAD
  phdr.p_flags = 5 # R + X
  phdr.p_offset = 0
  phdr.p_vaddr = phdr.p_paddr = BASE
  phdr.p_filesz = phdr.p_memsz = size
  phdr.p_align = 0x1000

  ehdr.to_binary_s + phdr.to_binary_s + code
end

def verify!(path, code)
  elf = ELFTools::ELFFile.new(File.open(path, 'rb'))
  raise "#{path}: wrong class" unless elf.elf_class == 64
  raise "#{path}: wrong machine" unless elf.header.e_machine == 62
  raise "#{path}: wrong entry" unless elf.header.e_entry == BASE + CODE_OFFSET

  load_seg = elf.segment_by_type(:load)
  raise "#{path}: code not covered by PT_LOAD" unless load_seg.file_head.zero? &&
                                                      load_seg.header.p_filesz == CODE_OFFSET + code.size
end

{ 'strict_prctl' => STRICT_PRCTL, 'strict_seccomp' => STRICT_SECCOMP }.each do |name, code|
  path = File.join(__dir__, name)
  File.binwrite(path, build_elf(code))
  File.chmod(0o755, path)
  verify!(path, code)
  puts "#{path}: OK"
end
