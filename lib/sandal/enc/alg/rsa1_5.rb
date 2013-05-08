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
        # @param key [OpenSSL::PKey::RSA or String] The key to use for CMK 
        # encryption (public) or decryption (private). If the value is a String 
        # then it will be passed to the constructor of the RSA class. This must 
        # be at least 2048 bits to be compliant with the JWA specification.
        def initialize(key)
          @name = 'RSA1_5'
          @key = key.is_a?(String) ? OpenSSL::PKey::RSA.new(key) : key
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
          raise Sandal::InvalidTokenError, 'Cannot decrypt content master key.'
        end

      end

    end
  end
end