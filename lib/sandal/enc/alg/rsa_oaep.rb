require 'openssl'

module Sandal
  module Enc
    module Alg

      # The RSAES with OAEP key encryption mechanism.
      class RSA_OAEP

        # @return [String] The JWA name of the algorithm.
        attr_reader :name

        # Creates a new instance.
        #
        # @param key [OpenSSL::PKey::RSA] The RSA public key used to protect the content master key.
        def initialize(key)
          @name = 'RSA-OAEP'
          @key = key
          @padding = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        end

        # Encrypts the content master key.
        #
        # @param cmk [String] The content master key.
        # @return [String] The encrypted content master key.
        def encrypt_cmk(cmk)
          @key.public_encrypt(cmk, @padding)
        end

        # Decrypts the content master key.
        #
        # @param encrypted_cmk [String] The encrypted content master key.
        # @return [String] The pre-shared content master key.
        # @raise [Sandal::TokenError] The content master key cannot be decrypted.
        def decrypt_cmk(encrypted_cmk)
          @key.private_decrypt(encrypted_cmk, @padding)
        rescue
          raise Sandal::TokenError, 'Failed to decrypt the content master key.'
        end

      end
      
    end
  end
end