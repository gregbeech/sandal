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
        r, s = self.class.decode_asn1_signature(asn1_sig)
        self.class.encode_jws_signature(r, s)
      end

      # Verifies a payload signature and returns whether the signature matches.
      def verify(signature, payload)
        hash = @digest.digest(payload)
        r, s = self.class.decode_jws_signature(signature)
        asn1_sig = self.class.encode_asn1_signature(r, s)
        @key.dsa_verify_asn1(hash, asn1_sig)
      end

      # Decodes an ASN1 signature into a pair of BNs.
      def self.decode_asn1_signature(signature)
        asn_seq = OpenSSL::ASN1.decode(signature)
        return asn_seq.value[0].value, asn_seq.value[1].value
      end

      # Encodes a pair of BNs into an ASN1 signature.
      def self.encode_asn1_signature(r, s)
        items = [OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]
        OpenSSL::ASN1::Sequence.new(items).to_der
      end

      # Decodes a JWS signature into a pair of BNs.
      def self.decode_jws_signature(signature)
        hex_string = Sandal::Util.base64_decode(signature)
        coord_length = hex_string.length / 2
        r = OpenSSL::BN.new(hex_string[0..(coord_length - 1)].unpack('H*')[0], 16)
        s = OpenSSL::BN.new(hex_string[coord_length..-1].unpack('H*')[0], 16)
        return r, s
      end

      # Encodes a pair of BNs into a JWS signature.
      def self.encode_jws_signature(r, s)  
        hex_string = [r.to_s(16) + s.to_s(16)].pack('H*')
        Sandal::Util.base64_encode(hex_string)
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