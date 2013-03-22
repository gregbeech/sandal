require 'openssl'
require 'sandal/jwa'

module Sandal
  module Enc

    # Base implementation of the AES/CBC family of encryption algorithms.
    class AESCBC
      include Sandal::Enc

      def initialize(aes_size, key)
        throw ArgumentError.new('A key is required.') unless key
        @aes_size = aes_size
        @sha_size = aes_size * 2
        @name = "A#{aes_size}CBC+HS#{@sha_size}"
        @alg_name = "RSA1_5" # TODO: From key?
        @cipher_name = "AES-#{aes_size}-CBC"
        @key = key
        @digest = OpenSSL::Digest.new("SHA#{@sha_size}")
      end

      def encrypt(header, payload)
        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        content_master_key = cipher.random_key
        iv = cipher.random_iv

        encrypted_key = @key.public_encrypt(content_master_key)
        encoded_encrypted_key = Sandal::JWA.base64_encode(encrypted_key)
        encoded_iv = Sandal::JWA.base64_encode(iv)

        cipher.key = derive_content_key('Encryption', content_master_key, @aes_size)
        ciphertext = cipher.update(payload) + cipher.final
        encoded_ciphertext = Sandal::JWA.base64_encode(ciphertext)

        encoded_header = Sandal::JWA.base64_encode(JSON.generate(header))
        secured_input = [encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext].join('.')
        content_integrity_key = derive_content_key('Integrity', content_master_key, @sha_size)
        integrity_value = OpenSSL::HMAC.digest(@digest, content_integrity_key, secured_input)
        encoded_integrity_value = Sandal::JWA.base64_encode(integrity_value)

        [secured_input, encoded_integrity_value].join('.')
      end

      private

      # Derives content keys using the Concat KDF.
      def derive_content_key(label, content_master_key, size)
        round_number = [1].pack('N')
        output_size = [size].pack('N')
        enc_bytes = @name.encode('utf-8').bytes.to_a.pack('C*')
        epu = epv = [0].pack('N')
        label_bytes = label.encode('us-ascii').bytes.to_a.pack('C*')
        hash_input = round_number + content_master_key + output_size + enc_bytes + epu + epv + label_bytes
        hash = @digest.digest(hash_input)
        hash[0..((size / 8) - 1)]
      end

    end

    class AES128CBC < Sandal::Enc::AESCBC
      def initialize(key)
        super(128, key)
      end
    end

    class AES256CBC < Sandal::Enc::AESCBC
      def initialize(key)
        super(256, key)
      end
    end

  end
end