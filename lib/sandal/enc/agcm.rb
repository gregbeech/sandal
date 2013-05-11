require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the A*GCM family of encryption methods.
    class AGCM
      include Sandal::Util

      # The JWA name of the encryption method.
      attr_reader :name

      # The JWA algorithm used to encrypt the content encryption key.
      attr_reader :alg

      # The size of key needed for the algorithm, in bits.
      attr_reader :key_size

      def initialize(aes_size, alg)
        @aes_size = aes_size
        @key_size = aes_size
        @name = "A#{aes_size}GCM"
        @cipher_name = "aes-#{aes_size}-gcm"
        @alg = alg
      end

      def encrypt(header, payload)
        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        key = @alg.respond_to?(:direct_key) ? @alg.direct_key : cipher.random_key
        encrypted_key = @alg.encrypt_key(key)

        cipher.key = key
        iv = cipher.random_iv

        auth_parts = [header, encrypted_key]
        auth_data = auth_parts.map { |part| jwt_base64_encode(part) }.join('.')
        cipher.auth_data  = auth_data

        ciphertext = cipher.update(payload) + cipher.final
        remaining_parts = [iv, ciphertext, cipher.auth_tag]
        remaining_parts.map! { |part| jwt_base64_encode(part) }
        [auth_data, *remaining_parts].join('.')
      end

      def decrypt(token)
        parts, decoded_parts = Sandal::Enc.token_parts(token)
        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        begin
          cipher.key = @alg.decrypt_key(decoded_parts[1])
          cipher.iv = decoded_parts[2]
          cipher.auth_tag = decoded_parts[4]
          cipher.auth_data = parts.take(2).join('.')
          cipher.update(decoded_parts[3]) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise Sandal::InvalidTokenError, 'Cannot decrypt token.'
        end
      end

    end

    # The A128GCM encryption method.
    class A128GCM < Sandal::Enc::AGCM

      # The size of key that is required, in bits.
      KEY_SIZE = 128

      def initialize(key)
        super(KEY_SIZE, key)
      end
    end

    # The A256GCM encryption method.
    class A256GCM < Sandal::Enc::AGCM

      # The size of key that is required, in bits.
      KEY_SIZE = 256

      def initialize(key)
        super(KEY_SIZE, key)
      end
    end

  end
end