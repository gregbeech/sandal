require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the AES/CBC+HMAC-SHA family of encryption algorithms.
    class ACBC_HS

      # The JWA name of the encryption.
      attr_reader :name

      # The JWA algorithm used to encrypt the content master key.
      attr_reader :alg

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
        encrypted_key = @alg.encrypt_cmk(content_master_key)

        cipher.key = derive_encryption_key(content_master_key) 
        iv = cipher.random_iv
        ciphertext = cipher.update(payload) + cipher.final

        secured_parts = [MultiJson.dump(header), encrypted_key, iv, ciphertext]
        secured_input = secured_parts.map { |part| Sandal::Util.base64_encode(part) }.join('.')
        content_integrity_key = derive_integrity_key(content_master_key)
        integrity_value = compute_integrity_value(content_integrity_key, secured_input)

        secured_input << '.' << Sandal::Util.base64_encode(integrity_value)
      end

      def decrypt(encrypted_key, iv, ciphertext, secured_input, integrity_value)
        begin
          content_master_key = @alg.decrypt_cmk(encrypted_key)
        rescue
          raise Sandal::TokenError, 'Failed to decrypt content master key.'
        end
        
        content_integrity_key = derive_integrity_key(content_master_key)
        computed_integrity_value = compute_integrity_value(content_integrity_key, secured_input)
        raise Sandal::TokenError, 'Invalid integrity value.' unless integrity_value == computed_integrity_value

        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        cipher.key = derive_encryption_key(content_master_key)
        cipher.iv = iv
        cipher.update(ciphertext) + cipher.final
      end

    private

      # Computes the integrity value.
      def compute_integrity_value(content_integrity_key, secured_input)
        OpenSSL::HMAC.digest(@digest, content_integrity_key, secured_input)
      end

      # Derives the content encryption key from the content master key.
      def derive_encryption_key(content_master_key)
        derive_content_key('Encryption', content_master_key, @aes_size)
      end

      # Derives the content integrity key from the content master key.
      def derive_integrity_key(content_master_key)
        derive_content_key('Integrity', content_master_key, @sha_size)
      end

      # Derives content keys using the Concat KDF.
      def derive_content_key(label, content_master_key, size)
        hash_input = [1].pack('N')
        hash_input << content_master_key
        hash_input << [size].pack('N')
        hash_input << @name.encode('utf-8')
        hash_input << [0].pack('N')
        hash_input << [0].pack('N')
        hash_input << label.encode('us-ascii')
        hash = @digest.digest(hash_input)
        hash[0..((size / 8) - 1)]
      end

    end

    # The AES-128-CBC+HMAC-SHA256 encryption algorithm.
    class A128CBC_HS256 < Sandal::Enc::ACBC_HS
      def initialize(key)
        super(128, 256, key)
      end
    end

    # The AES-256-CBC+HMAC-SHA512 encryption algorithm.
    class A256CBC_HS512 < Sandal::Enc::ACBC_HS
      def initialize(key)
        super(256, 512, key)
      end
    end

  end
end