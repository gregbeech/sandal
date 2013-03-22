require 'base64'

module Sandal
  # Implements some JWT utility functions. Shouldn't be needed by most people but may
  # be useful if you're developing an extension to the library.
  module Util
    
    # A string equality function which doesn't short-circuit the equality check to help
    # protect against timing attacks.
    #--
    # See http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/
    def self.secure_equals(a, b)
      if a.nil? && b.nil?
        true
      elsif a.nil? || b.nil? || a.bytesize != b.bytesize
        false
      else
        result = a.bytes.zip(b.bytes).reduce(0) { |memo, (b1, b2)| memo |= (b1 ^ b2) }
        result == 0
      end
    end

    # Base64 encodes a string, in compliance with the JWT specification.
    def self.base64_encode(s)
      Base64.urlsafe_encode64(s).gsub(%r{=+$}, '')
    end

    # Base64 decodes a string, in compliance with the JWT specification.
    def self.base64_decode(s)
      padding_length = (4 - (s.length % 4)) % 4
      padding = '=' * padding_length
      Base64.urlsafe_decode64(s + padding)
    end

  end
end