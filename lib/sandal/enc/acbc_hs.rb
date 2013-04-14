require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the AES/CBC+HMAC-SHA family of encryption algorithms.
    class ACBC_HS
      extend Sandal::Util

      # The JWA name of the encryption.
      attr_reader :name

      # The JWA algorithm used to encrypt the content master key.
      attr_reader :alg

      # Creates a new instance; it's probably easier to use one of the subclass constructors.
      #
      # @param aes_size [Integer] The size of the AES algorithm.
      # @param sha_size [Integer] The size of the SHA algorithm.
      # @param alg [#name, #encrypt_cmk, #decrypt_cmk] The algorithm to use to encrypt and/or decrypt the AES key.
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
        secured_input = secured_parts.map { |part| jwt_base64_encode(part) }.join('.')
        content_integrity_key = derive_integrity_key(content_master_key)
        integrity_value = compute_integrity_value(content_integrity_key, secured_input)

        secured_input << '.' << jwt_base64_encode(integrity_value)
      end

      def decrypt(parts, decoded_parts)
        content_master_key = @alg.decrypt_cmk(decoded_parts[1])
        
        content_integrity_key = derive_integrity_key(content_master_key)
        computed_integrity_value = compute_integrity_value(content_integrity_key, parts.take(4).join('.'))
        raise Sandal::TokenError, 'Invalid integrity value.' unless jwt_strings_equal?(decoded_parts[4], computed_integrity_value)

        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        cipher.key = derive_encryption_key(content_master_key)
        cipher.iv = decoded_parts[2]
        cipher.update(decoded_parts[3]) + cipher.final
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