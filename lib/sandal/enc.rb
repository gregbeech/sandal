module Sandal
  # Common encryption traits.
  module Enc

    # The JWA name of the encryption.
    attr_reader :name

    # The JWA name of the algorithm.
    attr_reader :alg_name

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

require 'sandal/enc/aescbc'
require 'sandal/enc/aesgcm'