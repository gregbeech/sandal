require 'helper'
require 'openssl'
require_relative 'shared_examples'

# TODO: These tests are really for the Sandal module rather than just the algorithm -- move them!

describe Sandal::Enc::A256CBC_HS512 do
  include_examples 'algorithm compatibility', Sandal::Enc::A256CBC_HS512
end

