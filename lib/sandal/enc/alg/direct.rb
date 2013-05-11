require 'openssl'

module Sandal
  module Enc
    module Alg

      # The direct ("dir") key encryption algorithm, which uses a pre-shared symmetric key.
      class Direct

        # @return [String] The JWA name of the algorithm.
        attr_reader :name

        # @return [String] The pre-shared symmetric key.
        attr_reader :direct_key

        # Creates a new instance.
        #
        # @param direct_key [String] The pre-shared symmetric key.
        def initialize(direct_key)
          @name = 'dir'
          @direct_key = direct_key
        end

        # Returns an empty string as the key is not included in JWE tokens using direct key exchange.
        #
        # @param key [String] This parameter is ignored.
        # @return [String] An empty string.
        def encrypt_key(key)
          ''
        end

        # Returns the pre-shared content master key.
        #
        # @param encrypted_key [String] The encrypted key.
        # @return [String] The pre-shared symmetric key.
        # @raise [Sandal::InvalidTokenError] encrypted_key is not nil or empty.
        def decrypt_key(encrypted_key)
          unless encrypted_key.nil? || encrypted_key.empty?
            raise Sandal::InvalidTokenError, 'Token must not include encrypted CMK.' 
          end
          @direct_key
        end

      end

    end
  end
end