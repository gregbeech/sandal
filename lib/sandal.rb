$:.unshift('.')

require 'base64'
require 'multi_json'
require 'openssl'

require 'sandal/version'
require 'sandal/claims'
require 'sandal/sig'
require 'sandal/enc'

# A library for creating and reading JSON Web Tokens (JWT).
module Sandal

  # The error that is raised when a token is invalid.
  class TokenError < StandardError; end

  # The default options for token handling.
  #
  # max_clock_skew:: The maximum clock skew, in seconds, when validating times.
  # valid_iss:: A list of valid token issuers, if issuer validation is required.
  # valid_aud:: A list of valid audiences, if audience validation is required.
  # validate_exp:: Whether the expiry date of the token is validated.
  # validate_nbf:: Whether the not-before date of the token is validated.
  # validate_integrity:: Whether the integrity value of encrypted (JWE) tokens is validated.
  # validate_signature:: Whether the signature of signed (JWS) tokens is validated.
  DEFAULT_OPTIONS = {
    max_clock_skew: 300,
    valid_iss: [],
    valid_aud: [],
    validate_exp: true,
    validate_nbf: true,
    validate_integrity: true,
    validate_signature: true
  }

  # Overrides the default options.
  #
  # @param defaults [Hash] The options to override (see {DEFAULT_OPTIONS} for details).
  # @return [Hash] The new default options.
  def self.default!(defaults)
    DEFAULT_OPTIONS.merge!(defaults)
  end

  # Creates a signed JSON Web Token.
  #
  # @param payload [String/Hash] The payload of the token. Hashes will be encoded as JSON.
  # @param signer [Sandal::Sig] The token signer, which may be nil for an unsigned token.
  # @param header_fields [Hash] Header fields for the token (note: do not include 'alg').
  # @return [String] A signed JSON Web Token.
  def self.encode_token(payload, signer, header_fields = nil)
    signer ||= Sandal::Sig::None.instance

    header = {}
    header['alg'] = signer.name if signer.name != Sandal::Sig::None.instance.name
    header = header_fields.merge(header) if header_fields

    payload = MultiJson.dump(payload) unless payload.is_a?(String)

    encoded_header = Sandal::Util.base64_encode(MultiJson.dump(header))
    encoded_payload = Sandal::Util.base64_encode(payload)
    secured_input = [encoded_header, encoded_payload].join('.')

    signature = signer.sign(secured_input)
    encoded_signature = Sandal::Util.base64_encode(signature)
    [secured_input, encoded_signature].join('.')
  end

  # Creates an encrypted JSON Web Token.
  #
  # @param payload [String] The payload of the token.
  # @param encrypter [Sandal::Enc] The token encrypter.
  # @param header_fields [Hash] Header fields for the token (note: do not include 'alg' or 'enc').
  # @return [String] An encrypted JSON Web Token.
  def self.encrypt_token(payload, encrypter, header_fields = nil)
    header = {}
    header['enc'] = encrypter.name
    header['alg'] = encrypter.alg_name
    header = header_fields.merge(header) if header_fields

    encrypter.encrypt(header, payload)
  end

  # Decodes and validates a JSON Web Token.
  #
  # The block is called with the token header as the first parameter, and should return the appropriate
  # {Sandal::Sig} to validate the signature. It can optionally have a second options parameter which can
  # be used to override the {DEFAULT_OPTIONS} on a per-token basis.
  #
  # @param token [String] The encoded JSON Web Token.
  # @yieldparam header [Hash] The JWT header values.
  # @yieldparam options [Hash] (Optional) A hash that can be used to override the default options.
  # @yieldreturn [Sandal::Sig] The signature validator.
  # @return [Hash/String] The payload of the token as a Hash if it was JSON, otherwise as a String.
  # @raise [Sandal::TokenError] The token format is invalid, or validation of the token failed.
  def self.decode_token(token)
    parts = token.split('.')
    header, payload, signature = decode_jws_parts(parts)

    options = DEFAULT_OPTIONS.clone
    validator = yield header, options if block_given?
    validator ||= Sandal::Sig::None.instance

    if options[:validate_signature]
      secured_input = parts.take(2).join('.')
      raise TokenError, 'Invalid signature.' unless validator.valid?(signature, secured_input)
    end

    claims = MultiJson.load(payload) rescue nil unless header['cty'] == 'JWT'
    claims.extend(Sandal::Claims).validate_claims(options) if claims

    claims || payload
  end

  # Decrypts an encrypted JSON Web Token.
  #
  # **NOTE: This method is likely to change, to allow more validation options**
  def self.decrypt_token(encrypted_token, &enc_finder)
    parts = encrypted_token.split('.')
    raise ArgumentError, 'Invalid token format.' unless parts.length == 5
    begin
      header = MultiJson.load(Sandal::Util.base64_decode(parts[0]))
      encrypted_key = Sandal::Util.base64_decode(parts[1])
      iv = Sandal::Util.base64_decode(parts[2])
      ciphertext = Sandal::Util.base64_decode(parts[3])
      integrity_value = Sandal::Util.base64_decode(parts[4])
    rescue
      raise ArgumentError, 'Invalid token encoding.'
    end

    enc = enc_finder.call(header)
    raise TokenError, 'No decryptor was found.' unless enc
    enc.decrypt(encrypted_key, iv, ciphertext, parts.take(4).join('.'), integrity_value)
  end

  private

  # Decodes the parts of a JWS token.
  def self.decode_jws_parts(parts)
    raise TokenError, 'Invalid token format.' unless [2, 3].include?(parts.length)
    begin
      header = MultiJson.load(Sandal::Util.base64_decode(parts[0]))
      payload = Sandal::Util.base64_decode(parts[1])
      signature = if parts.length > 2 then Sandal::Util.base64_decode(parts[2]) else '' end
    rescue
      raise TokenError, 'Invalid token encoding.'
    end
    return header, payload, signature
  end

end