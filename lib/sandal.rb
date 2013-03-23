$:.unshift('.')

require 'base64'
require 'json'
require 'openssl'

require 'sandal/version'
require 'sandal/sig'
require 'sandal/enc'

# A library for creating and reading JSON Web Tokens (JWT).
module Sandal

  # Creates a signed token.
  def self.encode_token(payload, sig, header_fields = nil)
    if header_fields && header_fields['enc']
      throw ArgumentError.new('The header cannot contain an "enc" parameter.')
    end
    sig ||= Sandal::Sig::None.instance

    header = {}
    header['alg'] = sig.name if sig.name != Sandal::Sig::None.instance.name
    header = header_fields.merge(header) if header_fields

    encoded_header = Sandal::Util.base64_encode(JSON.generate(header))
    encoded_payload = Sandal::Util.base64_encode(payload)
    secured_input = [encoded_header, encoded_payload].join('.')

    signature = sig.sign(secured_input)
    encoded_signature = Sandal::Util.base64_encode(signature)
    [secured_input, encoded_signature].join('.')
  end

  # Creates an encrypted token.
  def self.encrypt_token(payload, enc, header_fields = nil)
    header = {}
    header['enc'] = enc.name
    header['alg'] = enc.alg_name
    header = header_fields.merge(header) if header_fields

    enc.encrypt(header, payload)
  end

  # Decodes a token, verifying the signature if present.
  def self.decode_token(token, &sig_finder)
    parts = token.split('.')
    throw ArgumentError.new('Invalid token format.') unless [2, 3].include?(parts.length)
    begin
      header = JSON.parse(Sandal::Util.base64_decode(parts[0]))
      payload = Sandal::Util.base64_decode(parts[1])
      signature = if parts.length > 2 then Sandal::Util.base64_decode(parts[2]) else '' end
    rescue
      throw ArgumentError.new('Invalid token encoding.')
    end

    algorithm = header['alg']
    if algorithm && algorithm != 'none'
      throw SecurityError.new('The signature is missing.') unless signature.length > 0
      sig = sig_finder.call(header)
      throw SecurityError.new('No signature verifier was found.') unless sig
      secured_input = parts.take(2).join('.')
      throw ArgumentError.new('Invalid signature.') unless sig.verify(signature, secured_input)
    end

    payload
  end

  # Decrypts a token.
  def self.decrypt_token(encrypted_token, &enc_finder)
    parts = encrypted_token.split('.')
    throw ArgumentError.new('Invalid token format.') unless parts.length == 5
    begin
      header = JSON.parse(Sandal::Util.base64_decode(parts[0]))
      encrypted_key = Sandal::Util.base64_decode(parts[1])
      iv = Sandal::Util.base64_decode(parts[2])
      ciphertext = Sandal::Util.base64_decode(parts[3])
      integrity_value = Sandal::Util.base64_decode(parts[4])
    rescue
      throw ArgumentError.new('Invalid token encoding.')
    end

    enc = enc_finder.call(header)
    throw SecurityError.new('No decryptor was found.') unless enc
    enc.decrypt(encrypted_key, iv, ciphertext, parts.take(4).join('.'), integrity_value)
  end

end

if __FILE__ == $0

  # create payload
  issued_at = Time.now
  claims = JSON.generate({
    iss: 'example.org',
    aud: 'example.com',
    sub: 'user@example.org',
    iat: issued_at.to_i,
    exp: (issued_at + 3600).to_i
  })

  puts claims.to_s

  # sign and encrypt
  jws_key = OpenSSL::PKey::RSA.new(2048)
  sig = Sandal::Sig::RS256.new(jws_key)
  jws_token = Sandal.encode_token(claims.to_s, sig)

  puts jws_token

  jwe_key = OpenSSL::PKey::RSA.new(2048)
  enc = Sandal::Enc::AES128GCM.new(jwe_key.public_key)
  jwe_token = Sandal.encrypt_token(jws_token, enc, { 'cty' => 'JWT' })

  puts jwe_token

  jws_token_2 = Sandal.decrypt_token(jwe_token) { |header| Sandal::Enc::AES128CBC.new(jwe_key) }
  roundtrip_claims = Sandal.decode_token(jws_token_2) { |header| Sandal::Sig::RS256.new(jws_key.public_key) }

  puts roundtrip_claims

end