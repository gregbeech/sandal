require 'base64'

module Sandal
  module JWA

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