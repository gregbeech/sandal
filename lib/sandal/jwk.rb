module Sandal
  class JWK

    # The key type; identifies the cryptographic algorithm family used with the key.
    attr_accessor :kty

    # The indended use of the key, typically "enc" or "sig", though other values may be used.
    attr_accessor :use

    # The algorithm intended for use with the key.
    attr_accessor :alg

    # The identifier of the key
    attr_accessor :kid

    def to_h
      h = { "kty" => kty }
      h["use"] = use if use
    end

    def to_s
      MultiJson.dump(to_h)
    end

  end
end