require 'base64'

module Sandal
  # @private
  # Implements some JWT utility functions. Shouldn't be needed by most people but may
  # be useful if you're developing an extension to the library.
  module Util

  private
    
    # A string equality function that compares Unicode codepoints, and also doesn't short-circuit 
    # the equality check to help protect against timing attacks.
    #--
    # See http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/ for more info
    # about timing attacks.
    #++
    #
    # @param a [String] The first string.
    # @param b [String] The second string.
    # @return [Boolean] true if the strings are equal; otherwise false.
    def jwt_strings_equal?(a, b)
      return true if a.object_id == b.object_id
      return false if a.nil? || b.nil? || a.length != b.length
      a.codepoints.zip(b.codepoints).reduce(0) { |memo, (a, b)| memo |= a ^ b } == 0
    end

    # Base64 encodes a string, in compliance with the JWT specification.
    #
    # @param s [String] The string to encode.
    # @return [String] The encoded base64 string.
    def jwt_base64_encode(s)
      Base64.urlsafe_encode64(s).gsub(/=+$/, '')
    end

    # Base64 decodes a string, in compliance with the JWT specification.
    #
    # @param s [String] The base64 string to decode.
    # @return [String] The decoded string.
    # @raise [Sandal::TokenError] The base64 string contains padding.
    def jwt_base64_decode(s)
      raise Sandal::TokenError, 'Base64 strings cannot contain padding.' if s.end_with?('=')
      padding_length = (4 - (s.length % 4)) % 4
      padding = '=' * padding_length
      Base64.urlsafe_decode64(s + padding)
    end

  end
end