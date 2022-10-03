# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'seccomp-tools/version'

Gem::Specification.new do |s|
  s.name          = 'seccomp-tools'
  s.version       = ::SeccompTools::VERSION
  s.summary       = 'seccomp-tools'
  s.description   = <<-EOS
Provide useful tools to analyze seccomp rules.
Visit https://github.com/david942j/seccomp-tools for more details.
  EOS
  s.license       = 'MIT'
  s.authors       = ['david942j']
  s.email         = ['david942j@gmail.com']
  s.files         = Dir['lib/**/*.rb'] + Dir['lib/**/*.y'] +
                    Dir['lib/seccomp-tools/templates/*'] + Dir['bin/*'] + Dir['ext/**/*'] + %w(README.md)
  s.extensions    = %w[ext/ptrace/extconf.rb]
  s.executables   = 'seccomp-tools'

  s.metadata = {
    'bug_tracker_uri' => 'https://github.com/david942j/seccomp-tools/issues',
    'documentation_uri' => 'https://www.rubydoc.info/github/david942j/seccomp-tools/master',
    'homepage_uri' => 'https://github.com/david942j/seccomp-tools',
    'source_code_uri' => 'https://github.com/david942j/seccomp-tools'
  }

  s.required_ruby_version = '>= 2.6'

  s.add_development_dependency 'rake', '~> 13.0'
  s.add_development_dependency 'rake-compiler', '~> 1.0'
  s.add_development_dependency 'rspec', '~> 3.9'
  s.add_development_dependency 'rubocop', '~> 1'
  s.add_development_dependency 'simplecov', '~> 0.21'
  s.add_development_dependency 'yard', '~> 0.9'

  s.add_dependency 'os', '~> 1.1', '>= 1.1.1'
end
