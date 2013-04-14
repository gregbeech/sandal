require 'openssl'

module Sandal
  module Enc
    module Alg

      # The RSAES-PKCS1-V1_5 key encryption mechanism.
      class RSA1_5

        # @return [String] The JWA name of the algorithm.
        attr_reader :name

        # Creates a new instance.
        #
        # @param key [OpenSSL::PKey::RSA] The RSA public key used to protect the
        # content master key.
        def initialize(key)
          @name = 'RSA1_5'
          @key = key
        end

        # Encrypts the content master key.
        #
        # @param cmk [String] The content master key.
        # @return [String] The encrypted content master key.
        def encrypt_cmk(cmk)
          @key.public_encrypt(cmk)
        end

        # Decrypts the content master key.
        #
        # @param encrypted_cmk [String] The encrypted content master key.
        # @return [String] The pre-shared content master key.
        # @raise [Sandal::TokenError] The content master key can't be decrypted.
        def decrypt_cmk(encrypted_cmk)
          @key.private_decrypt(encrypted_cmk)
        rescue
          raise Sandal::TokenError, 'Cannot decrypt content master key.'
        end

      end

    end
  end
end