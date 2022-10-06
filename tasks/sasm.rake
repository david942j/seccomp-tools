# frozen_string_literal: true

desc 'Generate seccomp asm parser by using racc'
task :sasm do
  next if ENV['CI']

  sh 'racc', 'lib/seccomp-tools/asm/sasm.y'
end
