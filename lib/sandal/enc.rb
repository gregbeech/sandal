module Sandal
  # Common encryption traits.
  module Enc

    # The JWA name of the encryption.
    attr_reader :name

    # The JWA algorithm used to encrypt the content master key.
    attr_reader :alg

    # Encrypts a header and payload, and returns an encrypted token.
    def encrypt(header, payload)
      raise NotImplementedError, "#{@name}.encrypt is not implemented."
    end

    # Decrypts a token.
    def decrypt(encrypted_key, iv, ciphertext, secured_input, integrity_value)
      raise NotImplementedError, "#{@name}.decrypt is not implemented."
    end

  end
end

require 'sandal/enc/aescbc_hs'
require 'sandal/enc/aesgcm'

require 'sandal/enc/alg/direct'
require 'sandal/enc/alg/rsa1_5'
require 'sandal/enc/alg/rsa_oaep'