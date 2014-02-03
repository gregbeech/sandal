($LOAD_PATH << File.expand_path("../lib", __FILE__)).uniq!
require "sandal/version"

Gem::Specification.new do |s|
  s.name = "sandal"
  s.version = Sandal::VERSION
  s.summary = "A JSON Web Token (JWT) library."
  s.description = "A ruby library for creating and reading JSON Web Tokens (JWT), supporting JSON Web Signatures (JWS) and JSON Web Encryption (JWE)."
  s.author = "Greg Beech"
  s.email = "greg@gregbeech.com"
  s.homepage = "http://rubygems.org/gems/sandal"
  s.license = "MIT"

  s.files = `git ls-files`.split($/)
  s.executables = s.files.grep(%r{^bin/}) { |f| File.basename(f) }
  s.test_files = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = ["lib"]
  s.extra_rdoc_files = ["README.md", "LICENSE.md", "CHANGELOG.md"]

  s.add_runtime_dependency "jruby-openssl", "~> 0.7", ">= 0.7.3" if RUBY_PLATFORM == "java"

  s.add_development_dependency "bundler", ">= 1.3"
  s.add_development_dependency "rake", ">= 10.0"
  s.add_development_dependency "rspec", ">= 2.13"
  s.add_development_dependency "simplecov", ">= 0.7"
  s.add_development_dependency "coveralls", ">= 0.6"
  s.add_development_dependency "yard", ">= 0.8"
  s.add_development_dependency "redcarpet", ">= 2.2" unless RUBY_PLATFORM == "java" # for yard
  s.add_development_dependency "kramdown", ">= 1.0" if RUBY_PLATFORM == "java"      # for yard

  s.requirements << "OpenSSL 1.0.1c for EC signature methods (1.0.1f recommended)"
end