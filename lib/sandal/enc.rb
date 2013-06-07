require "openssl"
require "sandal/util"

module Sandal
  # Contains encryption (JWE) functionality.
  module Enc

    # Gets the decoded parts of a JWE token.
    #
    # @param token [String or Array] The token, or encoded token parts.
    # @return [[Array, Array]] The encoded parts and the decoded parts.
    def self.token_parts(token)
      parts = token.is_a?(Array) ? token : token.split(".")
      raise ArgumentError unless parts.length == 5
      decoded_parts = parts.map { |part| jwt_base64_decode(part) }
      return parts, decoded_parts
    rescue ArgumentError
      raise Sandal::InvalidTokenError, "Invalid token encoding."
    end

  end
end

require "sandal/enc/acbc_hs"
require "sandal/enc/agcm" unless RUBY_VERSION < "2.0.0"
require "sandal/enc/alg"