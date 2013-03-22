require 'openssl'

module Sandal
  module Sig

    # Base implementation of the RSA-SHA family of signature algorithms.
    class RS
      include Sandal::Sig

      # Creates a new instance with the size of the SHA algorithm and an OpenSSL PKey. To sign
      # a value this must contain a private key; to verify a signature a public key is sufficient.
      def initialize(sha_size, key)
        throw ArgumentError.new('A key is required.') unless key

        @name = "RS#{sha_size}"
        @digest = OpenSSL::Digest.new("SHA#{sha_size}")
        @key = key
      end

      # Signs data and returns the signature.
      def sign(data)
        throw ArgumentError.new('A private key is required to sign a message.') unless @key.private?
        @key.sign(@digest, data)
      end

      # Verifies a signature and returns whether the signature matches.
      def verify(signature, data)
        @key.verify(@digest, signature, data)
      end

    end

    # The RSA-SHA256 signing algorithm.
    class RS256 < Sandal::Sig::RS
      # Creates a new instance with an OpenSSL PKey.
      def initialize(key)
        super(256, key)
      end
    end

    # The RSA-SHA384 signing algorithm.
    class RS384 < Sandal::Sig::RS
      # Creates a new instance with an OpenSSL PKey.
      def initialize(key)
        super(384, key)
      end
    end

    # The RSA-SHA512 signing algorithm.
    class RS512 < Sandal::Sig::RS
      # Creates a new instance with an OpenSSL PKey.
      def initialize(key)
        super(512, key)
      end
    end

  end
end