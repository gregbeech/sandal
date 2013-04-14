require 'openssl'

module Sandal
  module Sig

    # Base implementation of the HMAC-SHA family of signature algorithms.
    class HS
      extend Sandal::Util

      # @return [String] The JWA name of the algorithm.
      attr_reader :name

      # Creates a new instance; it's probably easier to use one of the subclass constructors.
      #
      # @param sha_size [Integer] The size of the SHA algorithm.
      # @param key [String] The key to use for signing or validation.
      def initialize(sha_size, key)
        @name = "HS#{sha_size}"
        @digest = OpenSSL::Digest.new("sha#{sha_size}")
        @key = key
      end

      # Signs a payload and returns the signature.
      #
      # @param payload [String] The payload of the token to sign.
      # @return [String] The signature.
      def sign(payload)
        OpenSSL::HMAC.digest(@digest, @key, payload)
      end

      # Validates a payload signature and returns whether the signature matches.
      #
      # @param signature [String] The signature to verify.
      # @param payload [String] The payload of the token.
      # @return [Boolean] true if the signature is correct; otherwise false.
      def valid?(signature, payload)
        jwt_strings_equal?(sign(payload), signature)
      end

    end

    # The HMAC-SHA256 signing algorithm.
    class HS256 < Sandal::Sig::HS
      # Creates a new instance.
      #
      # @param key [String] The key to use for signing or validation.
      def initialize(key)
        super(256, key)
      end
    end

    # The HMAC-SHA384 signing algorithm.
    class HS384 < Sandal::Sig::HS
      # Creates a new instance.
      #
      # @param key [String] The key to use for signing or validation.
      def initialize(key)
        super(384, key)
      end
    end

    # The HMAC-SHA512 signing algorithm.
    class HS512 < Sandal::Sig::HS
      # Creates a new instance.
      #
      # @param key [String] The key to use for signing or validation.
      def initialize(key)
        super(512, key)
      end
    end

  end
end