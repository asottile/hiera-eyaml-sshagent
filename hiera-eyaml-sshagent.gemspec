# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'hiera/backend/eyaml/encryptors/sshagent/version'

Gem::Specification.new do |gem|
  gem.name          = 'hiera-eyaml-sshagent'
  gem.version       = Hiera::Backend::Eyaml::Encryptors::SSHAgent::VERSION
  gem.description   = 'SSH_AUTH_SOCK encryptor for use with hiera-eyaml'
  gem.summary       = 'Encryption plugin for hiera-eyaml backend for Hiera'
  gem.author        = 'Anthony Sottile'
  gem.license       = 'MIT'

  gem.homepage      = 'http://github.com/asottile/hiera-eyaml-sshagent'
  gem.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']

  gem.required_ruby_version = '>=2.6'
  gem.add_dependency('fernet', '>=2')
  gem.add_dependency('hiera-eyaml', '>=1.3.8')
  gem.metadata['rubygems_mfa_required'] = 'true'
end
