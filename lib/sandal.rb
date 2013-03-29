$:.unshift('.')

require 'base64'
require 'json'
require 'openssl'

require 'sandal/version'
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
  # @param payload [String/Hash] The payload of the token. If a Hash then it will be encoded as JSON.
  # @param signer [Sandal::Sig] The token signer, which may be nil for an unsigned token.
  # @param header_fields [Hash] Header fields for the token (note: do not include 'alg').
  # @return [String] A signed JSON Web Token.
  def self.encode_token(payload, signer, header_fields = nil)
    if header_fields && header_fields['enc']
      raise ArgumentError, 'The header cannot contain an "enc" parameter.'
    end
    signer ||= Sandal::Sig::None.instance

    header = {}
    header['alg'] = signer.name if signer.name != Sandal::Sig::None.instance.name
    header = header_fields.merge(header) if header_fields

    payload = JSON.generate(payload) if payload.kind_of?(Hash)

    encoded_header = Sandal::Util.base64_encode(JSON.generate(header))
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

  # Decodes a JSON Web Token, verifying the signature as necessary.
  #
  # @param token [String] The encoded JSON Web Token.
  # @return [Hash/String] The payload of the token as a Hash if it was JSON, otherwise as a String.
  # @yieldparam header [Hash] The JWT header values.
  # @yieldparam options [Hash] (Optional) A hash that can be used to override the default options.
  # @yieldreturn [Sandal::Sig] The signature verifier.
  def self.decode_token(token, &block)
    parts = token.split('.')
    raise TokenError, 'Invalid token format.' unless [2, 3].include?(parts.length)
    begin
      header = JSON.parse(Sandal::Util.base64_decode(parts[0]))
      payload = Sandal::Util.base64_decode(parts[1])
      signature = if parts.length > 2 then Sandal::Util.base64_decode(parts[2]) else '' end
    rescue
      raise TokenError, 'Invalid token encoding.'
    end

    options = DEFAULT_OPTIONS.clone
    if block
      case block.arity
      when 1 then verifier = block.call(header)
      when 2 then verifier = block.call(header, options)
      else raise ArgumentError, 'Incorrect number of block parameters.'
      end
    end    
    verifier ||= Sandal::Sig::None.instance

    if options[:validate_signature]
      secured_input = parts.take(2).join('.')
      raise TokenError, 'Invalid signature.' unless verifier.verify(signature, secured_input)
    end

    claims = JSON.parse(payload) rescue nil
    validate_claims(claims, options) if claims

    claims || payload
  end

  # Decrypts an encrypted JSON Web Token.
  #
  # **NOTE: This method is likely to change, to allow more validation options**
  def self.decrypt_token(encrypted_token, &enc_finder)
    parts = encrypted_token.split('.')
    raise ArgumentError, 'Invalid token format.' unless parts.length == 5
    begin
      header = JSON.parse(Sandal::Util.base64_decode(parts[0]))
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

  # Validates token claims according to the options
  def self.validate_claims(claims, options)
    validate_expires(claims, options)
    validate_not_before(claims, options)
    validate_issuer(claims, options)
    validate_audience(claims, options)
  end

  # Validates the 'exp' claim.
  def self.validate_expires(claims, options)
    if options[:validate_exp] && claims['exp']
      begin
        exp = Time.at(claims['exp'])
      rescue
        raise TokenError, 'The "exp" claim is invalid.'
      end
      raise TokenError, 'The token has expired.' unless exp > (Time.now - options[:max_clock_skew])
    end
  end

  # Validates the 'nbf' claim
  def self.validate_not_before(claims, options)
    if options[:validate_nbf] && claims['nbf']
      begin
        nbf = Time.at(claims['nbf'])
      rescue
        raise TokenError, 'The "nbf" claim is invalid.'
      end
      raise TokenError, 'The token is not valid yet.' unless nbf < (Time.now + options[:max_clock_skew])
    end
  end

  # Validates the 'iss' claim.
  def self.validate_issuer(claims, options)
    valid_iss = options[:valid_iss]
    if valid_iss && valid_iss.length > 0
      raise TokenError, 'The issuer is invalid.' unless valid_iss.include?(claims['iss'])
    end
  end

  # Validates the 'aud' claim.
  def self.validate_audience(claims, options)
    valid_aud = options[:valid_aud]
    if valid_aud && valid_aud.length > 0
      aud = claims['aud']
      aud = [aud] unless aud.kind_of?(Array)
      raise TokenError, 'The audence is invalid.' unless (aud & valid_aud).length > 0
    end
  end

end