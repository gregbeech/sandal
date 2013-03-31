require 'openssl'

module Sandal
  module Sig

    # Base implementation of the RSA-SHA family of signature algorithms.
    class RS

      # @return [String] The JWA name of the algorithm.
      attr_reader :name

      # Creates a new instance; it's probably easier to use one of the subclass constructors.
      #
      # @param sha_size [Integer] The size of the SHA algorithm.
      # @param key [OpenSSL::PKey::RSA] The key to use for signing (private) or validation (public). This must
      #   be at least 2048 bits to be compliant with the JWA specification.
      def initialize(sha_size, key)
        @name = "RS#{sha_size}"
        @digest = OpenSSL::Digest.new("sha#{sha_size}")
        @key = key
      end

      # Signs a payload and returns the signature.
      #
      # @param payload [String] The payload of the token to sign.
      # @return [String] The signature.
      def sign(payload)
        @key.sign(@digest, payload)
      end

      # Validates a payload signature and returns whether the signature matches.
      #
      # @param signature [String] The signature to verify.
      # @param payload [String] The payload of the token.
      # @return [Boolean] true if the signature is correct; otherwise false.
      def valid?(signature, payload)
        @key.verify(@digest, signature, payload)
      end

    end

    # The RSA-SHA256 signing algorithm.
    class RS256 < Sandal::Sig::RS
      # Creates a new instance.
      #
      # @param key [OpenSSL::PKey::RSA] The key to use for signing (private) or validation (public). This must
      #   be at least 2048 bits to be compliant with the JWA specification.
      def initialize(key)
        super(256, key)
      end
    end

    # The RSA-SHA384 signing algorithm.
    class RS384 < Sandal::Sig::RS
      # Creates a new instance.
      #
      # @param key [OpenSSL::PKey::RSA] The key to use for signing (private) or validation (public). This must
      #   be at least 2048 bits to be compliant with the JWA specification.
      def initialize(key)
        super(384, key)
      end
    end

    # The RSA-SHA512 signing algorithm.
    class RS512 < Sandal::Sig::RS
      # Creates a new instance.
      #
      # @param key [OpenSSL::PKey::RSA] The key to use for signing (private) or validation (public). This must
      #   be at least 2048 bits to be compliant with the JWA specification.
      def initialize(key)
        super(512, key)
      end
    end

  end
end