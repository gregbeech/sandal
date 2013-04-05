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

      def initialize(aes_size, alg)
        @aes_size = aes_size
        @name = "A#{aes_size}GCM"
        @cipher_name = "aes-#{aes_size}-gcm"
        @alg = alg
      end

      def encrypt(header, payload)
        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        content_master_key = @alg.respond_to?(:cmk) ? @alg.cmk : cipher.random_key
        encrypted_key = @alg.encrypt_cmk(content_master_key)

        cipher.key = content_master_key
        iv = cipher.random_iv

        auth_parts = [MultiJson.dump(header), encrypted_key, iv]
        auth_data = auth_parts.map { |part| Sandal::Util.base64_encode(part) }.join('.')
        cipher.auth_data  = auth_data

        ciphertext = cipher.update(payload) + cipher.final
        remainder = [ciphertext, cipher.auth_tag].map { |part| Sandal::Util.base64_encode(part) }.join('.')
        [auth_data, remainder].join('.')
      end

      def decrypt(parts, decoded_parts)
        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        cipher.key = @alg.decrypt_cmk(decoded_parts[1])
        cipher.iv = decoded_parts[2]
        cipher.auth_tag = decoded_parts[4]
        cipher.auth_data = parts.take(3).join('.')
        cipher.update(decoded_parts[3]) + cipher.final
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