require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the AES/CBC+HMAC-SHA family of encryption 
    # algorithms.
    class ACBC_HS
      extend Sandal::Util

      # The JWA name of the encryption.
      attr_reader :name

      # The JWA algorithm used to encrypt the content master key.
      attr_reader :alg

      # Creates a new instance; it's probably easier to use one of the subclass 
      # constructors.
      #
      # @param aes_size [Integer] The size of the AES algorithm.
      # @param sha_size [Integer] The size of the SHA algorithm.
      # @param alg [#name, #encrypt_cmk, #decrypt_cmk] The algorithm to use to 
      #   encrypt and/or decrypt the AES key.
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
        cmk = @alg.respond_to?(:cmk) ? @alg.cmk : cipher.random_key
        encrypted_key = @alg.encrypt_cmk(cmk)

        cipher.key = derive_encryption_key(cmk) 
        iv = cipher.random_iv
        ciphertext = cipher.update(payload) + cipher.final

        sec_parts = [MultiJson.dump(header), encrypted_key, iv, ciphertext]
        sec_input = sec_parts.map { |part| jwt_base64_encode(part) }.join('.')
        cik = derive_integrity_key(cmk)
        integrity_value = compute_integrity_value(cik, sec_input)

        sec_input << '.' << jwt_base64_encode(integrity_value)
      end

      def decrypt(parts, decoded_parts)
        cmk = @alg.decrypt_cmk(decoded_parts[1])
        
        cik = derive_integrity_key(cmk)
        integrity_value = compute_integrity_value(cik, parts.take(4).join('.'))
        unless jwt_strings_equal?(decoded_parts[4], integrity_value)
          raise Sandal::TokenError, 'Invalid integrity value.'
        end

        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        cipher.key = derive_encryption_key(cmk)
        cipher.iv = decoded_parts[2]
        cipher.update(decoded_parts[3]) + cipher.final
      end

    private

      # Computes the integrity value.
      def compute_integrity_value(cik, sec_input)
        OpenSSL::HMAC.digest(@digest, cik, sec_input)
      end

      # Derives the content encryption key from the content master key.
      def derive_encryption_key(cmk)
        derive_content_key('Encryption', cmk, @aes_size)
      end

      # Derives the content integrity key from the content master key.
      def derive_integrity_key(cmk)
        derive_content_key('Integrity', cmk, @sha_size)
      end

      # Derives content keys using the Concat KDF.
      def derive_content_key(label, cmk, size)
        hash_input = [1].pack('N')
        hash_input << cmk
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