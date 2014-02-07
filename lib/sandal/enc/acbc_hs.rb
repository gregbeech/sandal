require "openssl"
require "sandal/util"

module Sandal
  module Enc

    # Base implementation of the A*CBC-HS* family of encryption methods.
    class ACBC_HS

      # The JWA name of the encryption method.
      attr_reader :name

      # The JWA algorithm used to encrypt the content master key.
      attr_reader :alg

      # Initialises a new instance; it's probably easier to use one of the subclass constructors.
      #
      # @param name [String] The JWA name of the encryption method.
      # @param aes_size [Integer] The size of the AES algorithm, in bits.
      # @param sha_size [Integer] The size of the SHA algorithm, in bits.
      # @param alg [#name, #encrypt_key, #decrypt_key] The algorithm to use to encrypt and/or decrypt the AES key.
      def initialize(name, aes_size, sha_size, alg)
        @name = name
        @aes_size = aes_size
        @sha_size = sha_size
        @cipher_name = "aes-#{aes_size}-cbc"
        @alg = alg
        @digest = OpenSSL::Digest.new("sha#{@sha_size}")
      end

      # Encrypts a token payload.
      #
      # @param header [String] The header string.
      # @param payload [String] The payload.
      # @return [String] An encrypted JSON Web Token.
      def encrypt(header, payload)
        key = get_encryption_key
        mac_key, enc_key = derive_keys(key)
        encrypted_key = @alg.encrypt_key(key)

        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        cipher.key = enc_key
        cipher.iv = iv = SecureRandom.random_bytes(16)
        ciphertext = cipher.update(payload) + cipher.final

        auth_data = Sandal::Base64.encode(header)
        auth_data_length = [auth_data.length * 8].pack("Q>")
        mac_input = [auth_data, iv, ciphertext, auth_data_length].join
        mac = OpenSSL::HMAC.digest(@digest, mac_key, mac_input)
        auth_tag = mac[0...(mac.length / 2)]

        remainder = Sandal::Base64.encode([encrypted_key, iv, ciphertext, auth_tag])
        [auth_data, *remainder].join(".")
      end

      # Decrypts an encrypted JSON Web Token.
      #
      # @param token [String or Array] The token, or token parts, to decrypt.
      # @return [String] The token payload.
      def decrypt(token)
        parts, decoded_parts = Sandal::Enc.token_parts(token)
        header, encrypted_key, iv, ciphertext, auth_tag = *decoded_parts

        key = @alg.decrypt_key(encrypted_key)
        mac_key, enc_key = derive_keys(key)

        auth_data = parts[0]
        auth_data_length = [auth_data.length * 8].pack("Q>")
        mac_input = [auth_data, iv, ciphertext, auth_data_length].join
        mac = OpenSSL::HMAC.digest(@digest, mac_key, mac_input)
        unless auth_tag == mac[0...(mac.length / 2)]
          raise Sandal::InvalidTokenError, "Invalid authentication tag."
        end

        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        begin
          cipher.key = enc_key
          cipher.iv = decoded_parts[2]
          cipher.update(decoded_parts[3]) + cipher.final
        rescue OpenSSL::Cipher::CipherError => e
          raise Sandal::InvalidTokenError, "Cannot decrypt token: #{e.message}"
        end
      end

      private

      # Gets the key to use for mac and encryption
      def get_encryption_key
        key_bytes = @sha_size / 8
        if @alg.respond_to?(:preshared_key)
          key = @alg.preshared_key
          unless key.size == key_bytes
            raise Sandal::KeyError, "The pre-shared content key must be #{@sha_size} bits."
          end
          key
        else
          SecureRandom.random_bytes(key_bytes)
        end
      end

      # Derives the mac key and encryption key
      def derive_keys(key)
        derived_key_size = key.size / 2
        mac_key = key[0...derived_key_size]
        enc_key = key[derived_key_size..-1]
        return mac_key, enc_key
      end

    end

    # The A128CBC-HS256 encryption method.
    class A128CBC_HS256 < Sandal::Enc::ACBC_HS

      # The JWA name of the algorithm.
      NAME = "A128CBC-HS256"

      # The size of key that is required, in bits.
      KEY_SIZE = 256

      # Initialises a new instance.
      #
      # @param alg [#name, #encrypt_key, #decrypt_key] The algorithm to use to encrypt and/or decrypt the AES key.
      def initialize(alg)
        super(NAME, KEY_SIZE / 2, KEY_SIZE, alg)
      end

    end

    # The A256CBC-HS512 encryption method.
    class A256CBC_HS512 < Sandal::Enc::ACBC_HS

      # The JWA name of the algorithm.
      NAME = "A256CBC-HS512"

      # The size of key that is required, in bits.
      KEY_SIZE = 512

      # Initialises a new instance.
      #
      # @param alg [#name, #encrypt_key, #decrypt_key] The algorithm to use to encrypt and/or decrypt the AES key.
      def initialize(alg)
        super(NAME, KEY_SIZE / 2, KEY_SIZE, alg)
      end

    end

  end
end