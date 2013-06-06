require "openssl"

module Sandal
  module Enc
    module Alg

      # Base class for RSA key encryption algorithm.
      class RSA

        # @return [String] The JWA name of the algorithm.
        attr_reader :name

        # Initialises a new instance.
        #
        # @param rsa_key [OpenSSL::PKey::RSA or String] The RSA key to use for key encryption (public) or decryption 
        # (private). If the value is a String then it will be passed to the constructor of the RSA class. This must 
        # be at least 2048 bits to be compliant with the JWA specification.
        def initialize(rsa_key, padding)
          @name = self.class::NAME
          @rsa_key = rsa_key.is_a?(String) ? OpenSSL::PKey::RSA.new(rsa_key) : rsa_key
          @padding = padding
        end

        # Encrypts the content key.
        #
        # @param key [String] The content key.
        # @return [String] The encrypted content key.
        def encrypt_key(key)
          @rsa_key.public_encrypt(key, @padding)
        end

        # Decrypts the content key.
        #
        # @param encrypted_key [String] The encrypted content key.
        # @return [String] The pre-shared content key.
        # @raise [Sandal::TokenError] The content key can"t be decrypted.
        def decrypt_key(encrypted_key)
          @rsa_key.private_decrypt(encrypted_key, @padding)
        rescue => e
          raise Sandal::InvalidTokenError, "Cannot decrypt content key: #{e.message}"
        end

      end

      # The RSA1_5 key encryption algorithm.
      class RSA1_5 < RSA

        # The JWA name of the algorithm.
        NAME = "RSA1_5"

        # Initialises a new instance.
        #
        # @param rsa_key [OpenSSL::PKey::RSA or String] The RSA key to use for key encryption (public) or decryption 
        # (private). If the value is a String then it will be passed to the constructor of the RSA class. This must 
        # be at least 2048 bits to be compliant with the JWA specification.
        def initialize(rsa_key)
          super(rsa_key, OpenSSL::PKey::RSA::PKCS1_PADDING)
        end

      end

      # The RSA-OAEP key encryption algorithm.
      class RSA_OAEP < RSA

        # The JWA name of the algorithm.
        NAME = "RSA-OAEP"

        # Initialises a new instance.
        #
        # @param rsa_key [OpenSSL::PKey::RSA or String] The RSA key to use for key encryption (public) or decryption 
        # (private). If the value is a String then it will be passed to the constructor of the RSA class. This must 
        # be at least 2048 bits to be compliant with the JWA specification.
        def initialize(rsa_key)
          super(rsa_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        end

      end
      
    end
  end
end