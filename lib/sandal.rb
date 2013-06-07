require "multi_json"
require "openssl"
require "zlib"
require "sandal/version"
require "sandal/claims"
require "sandal/enc"
require "sandal/sig"
require "sandal/util"


# A library for creating and reading JSON Web Tokens (JWT), supporting JSON Web Signatures (JWS) and JSON Web Encryption
# (JWE).
#
# Currently supports draft-07 of the JWT spec, and draft-10 of the JWS and JWE specs.
module Sandal
  extend Sandal::Util

  # The base error for all errors raised by this library.
  class Error < StandardError; end

  # The error that is raised when a key provided for signing/encryption/etc. is invalid.
  class KeyError < Error; end

  # The error that is raised when there is a problem with a token.
  class TokenError < Error; end

  # The error that is raised when a token is invalid.
  class InvalidTokenError < TokenError; end

  # The error that is raised when a claim within a token is invalid.
  class ClaimError < InvalidTokenError; end

  # The error that is raised when the token has expired.
  class ExpiredTokenError < ClaimError; end

  # The error that is raised when a token is unsupported (e.g. the algorithm used to encrypt the token is not supported 
  # by this library or by the Ruby platform it is executing on).
  class UnsupportedTokenError < TokenError; end

  # The default options for token handling.
  #
  # ignore_exp:: 
  #   Whether to ignore the expiry date of the token. This setting is just to help get things working and should always
  #   be false in real apps!
  # ignore_nbf:: 
  #   Whether to ignore the not-before date of the token. This setting is just to help get things working and should
  #   always be false in real apps!
  # ignore_signature:: 
  #   Whether to ignore the signature of signed (JWS) tokens.  This setting is just tohelp get things working and should
  #   always be false in real apps!
  # max_clock_skew:: 
  #   The maximum clock skew, in seconds, when validating times. If your server time is out of sync with the token
  #   server then this can be increased to take that into account. It probably shouldn't be more than about 300.
  # valid_iss:: 
  #   A list of valid token issuers, if validation of the issuer claim is required.
  # valid_aud:: 
  #   A list of valid audiences, if validation of the audience claim is required.
  DEFAULT_OPTIONS = {
    ignore_exp: false,
    ignore_nbf: false,
    ignore_signature: false,
    max_clock_skew: 0,
    valid_iss: [],
    valid_aud: []
  }

  # Overrides the default options.
  #
  # @param defaults [Hash] The options to override (see {DEFAULT_OPTIONS} for details).
  # @return [Hash] The new default options.
  def self.default!(defaults)
    DEFAULT_OPTIONS.merge!(defaults)
  end

  # Checks whether a token is encrypted.
  #
  # @param token [String or Array] The token, or token parts.
  # @return [Boolean] true if the token is encrypted; otherwise false.
  def self.is_encrypted?(token)
    if token.is_a?(String)
      token.count(".") == 4
    else
      token.count == 5
    end
  end

  # Checks whether a token is signed.
  #
  # @param token [String or Array] The token, or token parts.
  # @return [Boolean] true if the token is signed; otherwise false.
  def self.is_signed?(token)
    if token.is_a?(String)
      !token.end_with?(".") && token.count(".") == 2
    else
      token.count == 3 && !token[2].nil? && !token[2].empty?
    end
  end

  # Creates a signed JSON Web Token.
  #
  # @param payload [String or Hash] The payload of the token. Hashes will be encoded as JSON.
  # @param signer [#name,#sign] The token signer, which may be nil for an unsigned token.
  # @param header_fields [Hash] Header fields for the token (note: do not include "alg").
  # @return [String] A signed JSON Web Token.
  def self.encode_token(payload, signer, header_fields = nil)
    signer ||= Sandal::Sig::NONE

    header = {}
    header["alg"] = signer.name
    header = header_fields.merge(header) if header_fields
    header = MultiJson.dump(header)

    payload = MultiJson.dump(payload) unless payload.is_a?(String)

    sec_input = [header, payload].map { |p| jwt_base64_encode(p) }.join(".")
    signature = signer.sign(sec_input)
    [sec_input, jwt_base64_encode(signature)].join(".")
  end

  # Creates an encrypted JSON Web Token.
  #
  # @param payload [String] The payload of the token.
  # @param encrypter [#name,#alg,#encrypt] The token encrypter.
  # @param header_fields [Hash] Header fields for the token (note: do not include "alg" or "enc").
  # @return [String] An encrypted JSON Web Token.
  def self.encrypt_token(payload, encrypter, header_fields = nil)
    header = {}
    header["enc"] = encrypter.name
    header["alg"] = encrypter.alg.name
    header = header_fields.merge(header) if header_fields

    if header.has_key?("zip")
      unless header["zip"] == "DEF"
        raise ArgumentError, "Invalid zip algorithm."
      end
      payload = Zlib::Deflate.deflate(payload, Zlib::BEST_COMPRESSION)
    end 

    encrypter.encrypt(MultiJson.dump(header), payload)
  end

  # Decodes and validates a signed and/or encrypted JSON Web Token, recursing into any nested tokens, and returns the 
  # payload.
  #
  # The block is called with the token header as the first parameter, and should return the appropriate signature or
  # decryption method to either validate the signature or decrypt the token as applicable. When the tokens are nested, 
  # this block will be called once per token. It can optionally have a second options parameter which can be used to
  # override the {DEFAULT_OPTIONS} on a per-token basis; options are not persisted between yields.
  #
  # @param token [String] The encoded JSON Web Token.
  # @param depth [Integer] The maximum depth of token nesting to decode to.
  # @yieldparam header [Hash] The JWT header values.
  # @yieldparam options [Hash] (Optional) A hash that can be used to override the default options.
  # @yieldreturn [#valid? or #decrypt] The signature validator if the token is signed, or the token decrypter if the
  #   token is encrypted.
  # @return [Hash or String] The payload of the token as a Hash if it was JSON, otherwise as a String.
  # @raise [Sandal::TokenError] The token is invalid or not supported.
  def self.decode_token(token, depth = 16)
    parts = token.split(".")
    decoded_parts = decode_token_parts(parts)
    header = decoded_parts[0]

    options = DEFAULT_OPTIONS.clone
    decoder = yield header, options if block_given?

    if is_encrypted?(parts)
      payload = decoder.decrypt(parts)
      if header.has_key?("zip")
        unless header["zip"] == "DEF"
          raise Sandal::InvalidTokenError, "Invalid zip algorithm."
        end
        payload = Zlib::Inflate.inflate(payload)
      end
    else
      payload = decoded_parts[1]
      unless options[:ignore_signature]
        validate_signature(parts, decoded_parts[2], decoder) 
      end
    end

    if header["cty"] == "JWT"
      if depth > 0
        if block_given?
          decode_token(payload, depth - 1, &Proc.new)
        else 
          decode_token(payload, depth - 1)
        end
      else
        payload
      end
    else
      parse_and_validate(payload, options)
    end
  end

  private

  # Decodes and validates a signed JSON Web Token.
  def self.validate_signature(parts, signature, validator)
    validator ||= Sandal::Sig::NONE
    secured_input = parts.take(2).join(".")
    unless validator.valid?(signature, secured_input)
      raise TokenError, "Invalid signature."
    end
  end

  # Decodes the parts of a token.
  def self.decode_token_parts(parts)
    parts = parts.map { |part| jwt_base64_decode(part) }
    parts[0] = MultiJson.load(parts[0])
    parts
  rescue
    raise TokenError, "Invalid token encoding."
  end

  # Parses the content of a token and validates the claims if is JSON claims.
  def self.parse_and_validate(payload, options)
    claims = MultiJson.load(payload) rescue nil
    if claims
      claims.extend(Sandal::Claims).validate_claims(options)
    else
      payload
    end
  end

end