require "openssl"

module Sandal
  module Enc
    module Alg

      # The direct ("dir") key encryption algorithm, which uses a pre-shared symmetric key.
      class Direct

        # The JWA name of the algorithm.
        NAME = "dir"

        # @return [String] The JWA name of the algorithm.
        attr_reader :name

        # @return [String] The pre-shared symmetric key.
        attr_reader :preshared_key

        # Initialises a new instance.
        #
        # @param preshared_key [String] The pre-shared symmetric key.
        def initialize(preshared_key)
          @name = NAME
          @preshared_key = preshared_key
        end

        # Returns an empty string as the key is not included in JWE tokens using direct key exchange.
        #
        # @param key [String] This parameter is ignored.
        # @return [String] An empty string.
        def encrypt_key(key)
          ""
        end

        # Returns the pre-shared content key.
        #
        # @param encrypted_key [String] The encrypted key.
        # @return [String] The pre-shared symmetric key.
        # @raise [Sandal::InvalidTokenError] encrypted_key is not nil or empty.
        def decrypt_key(encrypted_key)
          unless encrypted_key.nil? || encrypted_key.empty?
            raise Sandal::InvalidTokenError, "Tokens using direct key exchange must not include a content key."
          end
          @preshared_key
        end

      end

    end
  end
end