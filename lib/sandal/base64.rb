require "base64"

module Sandal
  # @private
  # Implements JWT compliant base64 encode/decode routines.
  module Base64

    # Encodes a string, or array of strings, as base64.
    #
    # @param s [String or Array] The string(s) to encode.
    # @return [String or Array] The encoded base64 string(s).
    def self.encode(s)
      if s.is_a?(String)
        ::Base64.urlsafe_encode64(s).gsub(/=+$/, "")
      else
        s.map { |e| encode(e) }
      end
    end

    # Decodes a base64 string, or array of strings.
    #
    # @param s [String] The base64 string(s) to decode.
    # @return [String] The decoded string(s).
    # @raise [ArgumentError] A base64 string is invalid or contains padding.
    def self.decode(s)
      if s.is_a?(String)
        raise ArgumentError, "Base64 strings must not contain padding." if s.end_with?("=")

        padding_length = (4 - (s.length % 4)) % 4
        padding = "=" * padding_length
        input = s + padding
        result = ::Base64.urlsafe_decode64(input)

        # this bit is primarily for jruby which does a "best effort" decode of whatever data it can if the input is 
        # invalid rather than raising an ArgumentError - as that could be a security issue we'll check that the 
        # result contains all the data that was in the input string
        raise ArgumentError, "Invalid base64." unless input.length == (((result.length - 1) / 3) * 4) + 4

        result
      else
        s.map { |e| decode(e) }
      end
    end

  end
end