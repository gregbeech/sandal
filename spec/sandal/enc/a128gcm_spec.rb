require 'helper'
require 'openssl'
require_relative 'shared_examples'

# TODO: These tests are really for the Sandal module rather than just the algorithm -- move them!

if defined? Sandal::Enc::A128GCM

describe Sandal::Enc::A128GCM do
  include_examples 'algorithm compatibility', Sandal::Enc::A128GCM
end

end