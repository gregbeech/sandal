require "base64"

module Sandal
  # @private
  # Implements some JWT utility functions. Shouldn't be needed by most people 
  # but may be useful if you're developing an extension to the library.
  module Util
    
    # A string equality function that compares Unicode codepoints, and also 
    # doesn't short-circuit the equality check to help protect against timing 
    # attacks.
    #--
    # http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/ 
    # for more info about timing attacks.
    #++
    #
    # @param a [String] The first string.
    # @param b [String] The second string.
    # @return [Boolean] true if the strings are equal; otherwise false.
    def self.strings_equal?(a, b)
      return true if a.object_id == b.object_id
      return false if a.nil? || b.nil? || a.length != b.length
      a.codepoints.zip(b.codepoints).reduce(0) { |r, (x, y)| r |= x ^ y } == 0
    end

    # Base64 encodes a string, in compliance with the JWT specification.
    #
    # @param s [String] The string to encode.
    # @return [String] The encoded base64 string.
    def self.base64_encode(s)
      Base64.urlsafe_encode64(s).gsub(/=+$/, "")
    end

    # Base64 decodes a string, in compliance with the JWT specification.
    #
    # @param s [String] The base64 string to decode.
    # @return [String] The decoded string.
    # @raise [ArgumentError] The base64 string is invalid or contains padding.
    def self.base64_decode(s)
      if s.end_with?("=")
        raise ArgumentError, "Base64 strings must not contain padding."
      end

      padding_length = (4 - (s.length % 4)) % 4
      padding = "=" * padding_length
      input = s + padding
      result = Base64.urlsafe_decode64(input)

      # this bit is primarily for jruby which does a "best effort" decode of
      # whatever data it can if the input is invalid rather than raising an
      # ArgumentError - as that could be a security issue we'll check that the 
      # result contains all the data that was in the input string
      unless input.length == (((result.length - 1) / 3) * 4) + 4
        raise ArgumentError, "Invalid base64."
      end
      
      result
    end

  end
end