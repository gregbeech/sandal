require 'openssl'

module Sandal
  module Sig

    # Base implementation of the RSA-SHA family of signature algorithms.
    class RS
      include Sandal::Sig

      # Creates a new instance with the size of the SHA algorithm and an OpenSSL RSA PKey. To sign
      # a value this must contain a private key; to verify a signature a public key is sufficient.
      # Note that the size of the RSA key must be at least 2048 bits to be compliant with the
      # JWA specification.
      def initialize(sha_size, key)
        throw ArgumentError.new('A key is required.') unless key
        @name = "RS#{sha_size}"
        @digest = OpenSSL::Digest.new("sha#{sha_size}")
        @key = key
      end

      # Signs a payload and returns the signature.
      def sign(payload)
        throw ArgumentError.new('A private key is required to sign the payload.') unless @key.private?
        @key.sign(@digest, payload)
      end

      # Verifies a payload signature and returns whether the signature matches.
      def verify(signature, payload)
        @key.verify(@digest, signature, payload)
      end

    end

    # The RSA-SHA256 signing algorithm.
    class RS256 < Sandal::Sig::RS
      # Creates a new instance with an OpenSSL RSA PKey.
      def initialize(key)
        super(256, key)
      end
    end

    # The RSA-SHA384 signing algorithm.
    class RS384 < Sandal::Sig::RS
      # Creates a new instance with an OpenSSL RSA PKey.
      def initialize(key)
        super(384, key)
      end
    end

    # The RSA-SHA512 signing algorithm.
    class RS512 < Sandal::Sig::RS
      # Creates a new instance with an OpenSSL RSA PKey.
      def initialize(key)
        super(512, key)
      end
    end

  end
end