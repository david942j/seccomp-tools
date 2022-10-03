# frozen_string_literal: true

desc 'Generate seccomp asm parser by using racc'
task :sasm do
  sh 'racc', 'lib/seccomp-tools/asm/sasm.y'
end
