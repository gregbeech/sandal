require 'base64'

module Sandal
  # Implements some JSON Web Algorithm helper functions.
  module JWA

    # A timing independent string comparison function to protect against timing attacks. See 
    # http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/ for details.
    def self.secure_compare(a, b)
      if a.nil? && b.nil?
        true
      elsif a.nil? || b.nil? || a.bytesize != b.bytesize
        false
      else
        result = a.bytes.zip(b.bytes).reduce(0) { |memo, (b1, b2)| memo |= b1 ^ b2 }
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