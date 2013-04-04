require 'coveralls'
Coveralls.wear!

require 'rspec'
require "#{File.dirname(__FILE__)}/../lib/sandal.rb"
RSpec.configure

def make_bn(arr)
  hex_str = arr.pack('C*').unpack('H*')[0]
  OpenSSL::BN.new(hex_str, 16)
end