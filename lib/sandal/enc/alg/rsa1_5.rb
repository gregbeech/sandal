require 'openssl'

module Sandal
  module Enc
    module Alg

      class RSA1_5

        attr_reader :name

        def initialize(key)
          @name = 'RSA1_5'
          @key = key
        end

        def encrypt_cmk(cmk)
          @key.public_encrypt(cmk)
        end

        def decrypt_cmk(encrypted_cmk)
          @key.private_decrypt(encrypted_cmk)
        end

      end

    end
  end
end