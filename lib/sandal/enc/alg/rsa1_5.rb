require 'openssl'

module Sandal
  module Enc
    module Alg

      # The RSA1_5 key encryption algorithm.
      class RSA1_5

        # @return [String] The JWA name of the algorithm.
        attr_reader :name

        # Creates a new instance.
        #
        # @param rsa_key [OpenSSL::PKey::RSA or String] The RSA key to use for key encryption (public) or decryption 
        # (private). If the value is a String then it will be passed to the constructor of the RSA class. This must 
        # be at least 2048 bits to be compliant with the JWA specification.
        def initialize(rsa_key)
          @name = 'RSA1_5'
          @rsa_key = rsa_key.is_a?(String) ? OpenSSL::PKey::RSA.new(rsa_key) : rsa_key
        end

        # Encrypts the content master key.
        #
        # @param key [String] The content master key.
        # @return [String] The encrypted content master key.
        def encrypt_key(key)
          @rsa_key.public_encrypt(key)
        end

        # Decrypts the content master key.
        #
        # @param encrypted_key [String] The encrypted content master key.
        # @return [String] The pre-shared content master key.
        # @raise [Sandal::TokenError] The content master key can't be decrypted.
        def decrypt_key(encrypted_key)
          @rsa_key.private_decrypt(encrypted_key)
        rescue
          raise Sandal::InvalidTokenError, 'Cannot decrypt content key.'
        end

      end

    end
  end
end