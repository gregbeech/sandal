require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the AES/CBC+HMAC-SHA family of encryption algorithms.
    class AESCBC_HS
      include Sandal::Enc

      def initialize(aes_size, sha_size, alg)
        @aes_size = aes_size
        @sha_size = sha_size
        @name = "A#{aes_size}CBC+HS#{@sha_size}"
        @cipher_name = "aes-#{aes_size}-cbc"
        @alg = alg
        @digest = OpenSSL::Digest.new("sha#{@sha_size}")
      end

      def encrypt(header, payload)
        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        content_master_key = @alg.respond_to?(:cmk) ? @alg.cmk : cipher.random_key
        iv = cipher.random_iv

        encrypted_key = @alg.encrypt_cmk(content_master_key)
        encoded_encrypted_key = Sandal::Util.base64_encode(encrypted_key)
        encoded_iv = Sandal::Util.base64_encode(iv)

        cipher.key = derive_content_key('Encryption', content_master_key, @aes_size)
        ciphertext = cipher.update(payload) + cipher.final
        encoded_ciphertext = Sandal::Util.base64_encode(ciphertext)

        encoded_header = Sandal::Util.base64_encode(MultiJson.dump(header))
        secured_input = [encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext].join('.')
        content_integrity_key = derive_content_key('Integrity', content_master_key, @sha_size)
        integrity_value = OpenSSL::HMAC.digest(@digest, content_integrity_key, secured_input)
        encoded_integrity_value = Sandal::Util.base64_encode(integrity_value)

        [secured_input, encoded_integrity_value].join('.')
      end

      def decrypt(encrypted_key, iv, ciphertext, secured_input, integrity_value)
        content_master_key = @alg.decrypt(encrypted_key)

        content_integrity_key = derive_content_key('Integrity', content_master_key, @sha_size)
        computed_integrity_value = OpenSSL::HMAC.digest(@digest, content_integrity_key, secured_input)
        raise ArgumentError, 'Invalid signature.' unless integrity_value == computed_integrity_value

        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        cipher.key = derive_content_key('Encryption', content_master_key, @aes_size)
        cipher.iv = iv
        cipher.update(ciphertext) + cipher.final
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

    # The AES-128-CBC+HMAC-SHA256 encryption algorithm.
    class AES128CBC_HS256 < Sandal::Enc::AESCBC_HS
      def initialize(key)
        super(128, 256, key)
      end
    end

    # The AES-256-CBC+HMAC-SHA512 encryption algorithm.
    class AES256CBC_HS512 < Sandal::Enc::AESCBC_HS
      def initialize(key)
        super(256, 512, key)
      end
    end

  end
end