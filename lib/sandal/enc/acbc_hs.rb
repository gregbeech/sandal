require 'openssl'
require 'sandal/util'

module Sandal
  module Enc

    # Base implementation of the A*CBC-HS* family of encryption methods.
    class ACBC_HS
      include Sandal::Util

      # The JWA name of the encryption method.
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
        @name = "A#{aes_size}CBC-HS#{@sha_size}"
        @cipher_name = "aes-#{aes_size}-cbc"
        @alg = alg
        @digest = OpenSSL::Digest.new("sha#{@sha_size}")
      end

      def encrypt(header, payload)
        key = get_encryption_key
        mac_key, enc_key = derive_keys(key)
        encrypted_key = @alg.encrypt_cmk(key)

        cipher = OpenSSL::Cipher.new(@cipher_name).encrypt
        cipher.key = enc_key
        iv = cipher.random_iv
        ciphertext = cipher.update(payload) + cipher.final

        auth_data = [MultiJson.dump(header), encrypted_key].map { |part| jwt_base64_encode(part) }.join('.')
        auth_data_length = [auth_data.length * 8].pack('Q>')
        mac_input = [auth_data, iv, ciphertext, auth_data_length].join
        mac = OpenSSL::HMAC.digest(@digest, mac_key, mac_input)
        auth_tag = mac[0...(mac.length / 2)]

        remainder = [iv, ciphertext, auth_tag].map { |part| jwt_base64_encode(part) }.join('.')
        [auth_data, remainder].join('.')
      end

      def decrypt(token)
        parts, decoded_parts = Sandal::Enc.token_parts(token)
        header, encrypted_key, iv, ciphertext, auth_tag = *decoded_parts

        key = @alg.decrypt_cmk(encrypted_key)
        mac_key, enc_key = derive_keys(key)

        auth_data = parts.take(2).join('.')
        auth_data_length = [auth_data.length * 8].pack('Q>')
        mac_input = [auth_data, iv, ciphertext, auth_data_length].join
        mac = OpenSSL::HMAC.digest(@digest, mac_key, mac_input)
        unless auth_tag == mac[0...(mac.length / 2)]
          raise Sandal::InvalidTokenError, 'Invalid integrity value.'
        end

        cipher = OpenSSL::Cipher.new(@cipher_name).decrypt
        begin
          cipher.key = enc_key
          cipher.iv = decoded_parts[2]
          cipher.update(decoded_parts[3]) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise Sandal::InvalidTokenError, 'Cannot decrypt token.'
        end
      end

      private

      # Gets the key to use for mac and encryption
      def get_encryption_key
        key_size = @sha_size / 8
        if @alg.respond_to?(:direct_key)
          key = @alg.direct_key
          unless key.size == key_size
            raise Sandal::KeyError, "The direct key must be #{@key_size * 8} bits"
          end
          key
        else
          SecureRandom.random_bytes(key_size)
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
      def initialize(key)
        super(128, 256, key)
      end
    end

    # The A256CBC-HS512 encryption method.
    class A256CBC_HS512 < Sandal::Enc::ACBC_HS
      def initialize(key)
        super(256, 512, key)
      end
    end

  end
end