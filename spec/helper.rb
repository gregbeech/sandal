require 'coveralls'
Coveralls.wear!

require 'rspec'
RSpec.configure do |c|
  c.treat_symbols_as_metadata_keys_with_true_values = true
  c.filter_run_excluding :timing_dependent # these are unreliable so don't run unless specified explicitly
  c.filter_run_excluding :jruby_incompatible if RUBY_PLATFORM == 'java'
end

def make_bn(arr)
  hex_str = arr.pack('C*').unpack('H*')[0]
  OpenSSL::BN.new(hex_str, 16)
end

require "#{File.dirname(__FILE__)}/../lib/sandal.rb"