module Sandal
  module Enc
    # Contains key encryption algorithms for JWE.
    module Alg
    end
  end
end

require 'sandal/enc/alg/direct'
require 'sandal/enc/alg/rsa1_5'
require 'sandal/enc/alg/rsa_oaep'