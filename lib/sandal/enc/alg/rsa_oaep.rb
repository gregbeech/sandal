require 'openssl'

module Sandal
  module Enc
    module Alg

      class RSA_OAEP

        attr_reader :name

        def initialize(key)
          @name = 'RSA-OAEP'
          @key = key
          @padding = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        end

        def encrypt_cmk(cmk)
          @key.public_encrypt(cmk, @padding)
        end

        def decrypt_cmk(encrypted_cmk)
          @key.private_decrypt(encrypted_cmk, @padding)
        end

      end
      
    end
  end
end