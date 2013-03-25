require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the AES/CBC family of encryption algorithms.
    class AESCBC
      include Sandal::Enc

      def initialize(aes_size, key)
        throw ArgumentError.new('A key is required.') unless key
        @aes_size = aes_size
        @sha_size = aes_size * 2 # TODO: Any smarter way to do this?
        @name = "A#{aes_size}CBC+HS#{@sha_size}"
        @alg_name = "RSA1_5" # TODO: From key?
        @cipher_name = "aes-#{aes_size}-cbc"
        @key = key
        @digest = OpenSSL::Digest.new("sha#{@sha_size}")
      end

      def encrypt(header, payload)
        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        content_master_key = cipher.random_key # TODO: Check with the spec if this is long enough
        iv = cipher.random_iv

        # TODO: Need to think about how this works with pre-shared symmetric keys - I'd originally thought
        # this wouldn't be a common use case, but in cases where the recipient is also the issuer (e.g.
        # an OAuth refresh token) then it would make a lot of sense.
        encrypted_key = @key.public_encrypt(content_master_key)
        encoded_encrypted_key = Sandal::Util.base64_encode(encrypted_key)
        encoded_iv = Sandal::Util.base64_encode(iv)

        cipher.key = derive_content_key('Encryption', content_master_key, @aes_size)
        ciphertext = cipher.update(payload) + cipher.final
        encoded_ciphertext = Sandal::Util.base64_encode(ciphertext)

        encoded_header = Sandal::Util.base64_encode(JSON.generate(header))
        secured_input = [encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext].join('.')
        content_integrity_key = derive_content_key('Integrity', content_master_key, @sha_size)
        integrity_value = OpenSSL::HMAC.digest(@digest, content_integrity_key, secured_input)
        encoded_integrity_value = Sandal::Util.base64_encode(integrity_value)

        [secured_input, encoded_integrity_value].join('.')
      end

      def decrypt(encrypted_key, iv, ciphertext, secured_input, integrity_value)
        content_master_key = @key.private_decrypt(encrypted_key)

        content_integrity_key = derive_content_key('Integrity', content_master_key, @sha_size)
        computed_integrity_value = OpenSSL::HMAC.digest(@digest, content_integrity_key, secured_input)
        throw ArgumentError.new('Invalid signature.') unless integrity_value == computed_integrity_value

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

    # The AES-128-CBC encryption algorithm.
    class AES128CBC < Sandal::Enc::AESCBC
      def initialize(key)
        super(128, key)
      end
    end

    # The AES-256-CBC encryption algorithm.
    class AES256CBC < Sandal::Enc::AESCBC
      def initialize(key)
        super(256, key)
      end
    end

  end
end