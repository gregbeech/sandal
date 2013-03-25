require 'openssl'

module Sandal
  module Sig

    # Base implementation of the HMAC-SHA family of signature algorithms.
    class HS
      include Sandal::Sig

      # Creates a new instance with the size of the SHA algorithm and a string key.
      def initialize(sha_size, key)
        throw ArgumentError.new('A key is required.') unless key
        @name = "HS#{sha_size}"
        @digest = OpenSSL::Digest.new("sha#{sha_size}")
        @key = key
      end

      # Signs a payload and returns the signature.
      def sign(payload)
        OpenSSL::HMAC.digest(@digest, @key, payload)
      end

      # Verifies a payload signature and returns whether the signature matches.
      def verify(signature, payload)
        Sandal::Util.secure_equals(sign(payload), signature)
      end

    end

    # The HMAC-SHA256 signing algorithm.
    class HS256 < Sandal::Sig::HS
      # Creates a new instance with a string key.
      def initialize(key)
        super(256, key)
      end
    end

    # The HMAC-SHA384 signing algorithm.
    class HS384 < Sandal::Sig::HS
      # Creates a new instance with a string key.
      def initialize(key)
        super(384, key)
      end
    end

    # The HMAC-SHA512 signing algorithm.
    class HS512 < Sandal::Sig::HS
      # Creates a new instance with a string key.
      def initialize(key)
        super(512, key)
      end
    end

  end
end