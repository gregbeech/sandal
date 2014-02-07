require "openssl"
require "sandal/util"

module Sandal
  module Enc

    # Base implementation of the A*GCM family of encryption methods.
    class AGCM

      @@iv_size = 96
      @@auth_tag_size = 128

      # The JWA name of the encryption method.
      attr_reader :name

      # The JWA algorithm used to encrypt the content encryption key.
      attr_reader :alg

      # Initialises a new instance; it's probably easier to use one of the subclass constructors.
      #
      # @param aes_size [Integer] The size of the AES algorithm, in bits.
      # @param alg [#name, #encrypt_key, #decrypt_key] The algorithm to use to encrypt and/or decrypt the AES key.
      def initialize(name, aes_size, alg)
        @name = name
        @aes_size = aes_size
        @cipher_name = "aes-#{aes_size}-gcm"
        @alg = alg
      end

      # Encrypts a token payload.
      #
      # @param header [String] The header string.
      # @param payload [String] The payload.
      # @return [String] An encrypted JSON Web Token.
      def encrypt(header, payload)
        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        key = @alg.respond_to?(:preshared_key) ? @alg.preshared_key : cipher.random_key
        encrypted_key = @alg.encrypt_key(key)

        cipher.key = key
        cipher.iv = iv = SecureRandom.random_bytes(@@iv_size / 8)

        auth_data = Sandal::Base64.encode(header)
        cipher.auth_data  = auth_data

        ciphertext = cipher.update(payload) + cipher.final
        remaining_parts = [encrypted_key, iv, ciphertext, cipher.auth_tag(@@auth_tag_size / 8)]
        remaining_parts = Sandal::Base64.encode(remaining_parts)
        [auth_data, *remaining_parts].join(".")
      end

      # Decrypts an encrypted JSON Web Token.
      #
      # @param token [String or Array] The token, or token parts, to decrypt.
      # @return [String] The token payload.
      def decrypt(token)
        parts, decoded_parts = Sandal::Enc.token_parts(token)
        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        begin
          cipher.key = @alg.decrypt_key(decoded_parts[1])
          cipher.iv = decoded_parts[2]
          cipher.auth_tag = decoded_parts[4]
          cipher.auth_data = parts[0]
          cipher.update(decoded_parts[3]) + cipher.final
        rescue OpenSSL::Cipher::CipherError => e
          raise Sandal::InvalidTokenError, "Cannot decrypt token: #{e.message}"
        end
      end

    end

    # The A128GCM encryption method.
    class A128GCM < Sandal::Enc::AGCM

      # The JWA name of the algorithm.
      NAME = "A128GCM"

      # The size of key that is required, in bits.
      KEY_SIZE = 128

      # Initialises a new instance.
      #
      # @param alg [#name, #encrypt_key, #decrypt_key] The algorithm to use to encrypt and/or decrypt the AES key.
      def initialize(alg)
        super(NAME, KEY_SIZE, alg)
      end

    end

    # The A256GCM encryption method.
    class A256GCM < Sandal::Enc::AGCM

      # The JWA name of the algorithm.
      NAME = "A256GCM"

      # The size of key that is required, in bits.
      KEY_SIZE = 256

      # Initialises a new instance.
      #
      # @param alg [#name, #encrypt_key, #decrypt_key] The algorithm to use to encrypt and/or decrypt the AES key.
      def initialize(alg)
        super(NAME, KEY_SIZE, alg)
      end

    end

  end
end