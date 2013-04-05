module Sandal
  # Contains encryption (JWE) functionality.
  module Enc
  end
end

require 'sandal/enc/acbc_hs'
require 'sandal/enc/agcm' unless RUBY_VERSION < '2.0.0'
require 'sandal/enc/alg'