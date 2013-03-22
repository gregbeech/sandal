($LOAD_PATH << File.expand_path("../lib", __FILE__)).uniq!
require 'sandal/version'

Gem::Specification.new do |s|
  s.name = 'sandal'
  s.version = Sandal::VERSION
  s.summary = 'A JSON Web Token (JWT) library.'
  s.description = 'A ruby library for creating and reading JSON Web Tokens (JWT), supporting JSON Web Signatures (JWS) and JSON Web Encryption (JWE).'
  s.authors = ['Greg Beech']
  s.email = ['greg@gregbeech.com']

  s.files = Dir['lib/**/*']
  s.homepage = 'http://rubygems.org/gems/sandal'
  s.license = 'MIT'
end