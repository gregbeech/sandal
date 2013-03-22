require 'openssl'

module Sandal
  module Sig

    class RS
      include Sandal::Sig

      def initialize(size, key)
        @name = "RS#{size}"
        @digest = OpenSSL::Digest.new("SHA#{size}")
        @key = key
      end

      def name
        @name
      end

      def sign(data)
        @key.sign(@digest, data)
      end

      def verify(signature, data)
        @key.verify(@digest, signature, data)
      end

    end

    class RS256 < Sandal::Sig::RS
      def initialize(private_key)
        super(256, private_key)
      end
    end

    class RS384 < Sandal::Sig::RS
      def initialize(private_key)
        super(384, private_key)
      end
    end

    class RS512 < Sandal::Sig::RS
      def initialize(private_key)
        super(512, private_key)
      end
    end

  end
end