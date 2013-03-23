require 'openssl'

module Sandal
  module Sig

    # Base implementation of the ECDSA-SHA family of signature algorithms.
    class ES
      include Sandal::Sig

      # Creates a new instance with the size of the SHA algorithm and an OpenSSL ES PKey.
      def initialize(sha_size, key)
        throw ArgumentError.new('A key is required.') unless key
        @name = "ES#{sha_size}"
        @digest = OpenSSL::Digest.new("SHA#{sha_size}")
        @key = key
      end

      # Signs a payload and returns the signature.
      def sign(payload)
        hash = @digest.digest(payload)
        asn1_sig = @key.dsa_sign_asn1(hash)
        r, s = asn1_decode(asn1_sig)
        Sandal::Util.base64_encode([r.to_s(16) + s.to_s(16)].pack('H*'))
      end

      # Verifies a payload signature and returns whether the signature matches.
      def verify(signature, payload)
        packed_sig = Sandal::Util.base64_decode(signature)
        r = OpenSSL::BN.new(packed_sig[0..31].unpack('H*')[0], 16)
        s = OpenSSL::BN.new(packed_sig[32..64].unpack('H*')[0], 16)
        asn1_sig = asn1_encode(r, s)
        hash = @digest.digest(payload)
        @key.dsa_verify_asn1(hash, asn1_sig)
      end

      private

      # Decodes an ASN1 signature into a pair of BNs.
      def self.asn1_decode(signature)
        asn1 = OpenSSL::ASN1.decode(signature)
        return asn1.value[0].value, asn1.value[1].value
      end

      # Encodes a pair of BNs into an ASN1 signature.
      def self.asn1_encode(r, s)
        items = [OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]
        OpenSSL::ASN1::Sequence.new(items).to_der
      end

    end

    # The ECDSA-SHA256 signing algorithm.
    class ES256 < Sandal::Sig::ES
      # Creates a new instance with an OpenSSL ES PKey.
      def initialize(key)
        super(256, key)
      end
    end

    # The ECDSA-SHA384 signing algorithm.
    class ES384 < Sandal::Sig::ES
      # Creates a new instance with an OpenSSL ES PKey.
      def initialize(key)
        super(384, key)
      end
    end

    # The ECDSA-SHA512 signing algorithm.
    class ES512 < Sandal::Sig::ES
      # Creates a new instance with an OpenSSL ES PKey.
      def initialize(key)
        super(512, key)
      end
    end

  end
end