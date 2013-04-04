require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the AES/GCM family of encryption algorithms.
    class AGCM

      # The JWA name of the encryption.
      attr_reader :name

      # The JWA algorithm used to encrypt the content master key.
      attr_reader :alg

      def initialize(aes_size, key)
        raise NotImplementedException, 'AES-CGM is not yet implemented.'
      end

      def encrypt(header, payload)
        raise NotImplementedException, 'AES-CGM is not yet implemented.'
      end

      def decrypt(encrypted_key, iv, ciphertext, secured_input, integrity_value)
        raise NotImplementedException, 'AES-CGM is not yet implemented.'
      end

    end

    # The AES-128-GCM encryption algorithm.
    class A128GCM < Sandal::Enc::AGCM
      def initialize(key)
        super(128, key)
      end
    end

    # The AES-256-GCM encryption algorithm.
    class A256GCM < Sandal::Enc::AGCM
      def initialize(key)
        super(256, key)
      end
    end

  end
end