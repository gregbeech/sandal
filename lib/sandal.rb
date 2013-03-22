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
    sig ||= Sandal::Sig::None.new

    header = {}
    header['alg'] = sig.name if sig.name != 'none'
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
  def self.decrypt_token(encrypted_token, &key_finder)
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

    algorithm = header['alg']
    encryption = header['enc']
    case encryption 
    when 'A128CBC+HS256', 'A256CBC+HS512'
      aes_length = Integer(encryption[1..3])
      sha_length = Integer(encryption[-3..-1])

      digest = OpenSSL::Digest.new("SHA#{sha_length}")

      private_key = key_finder.call(header)
      throw SecurityError.new('No key was found to decrypt the content master key.') unless private_key
      content_master_key = private_key.private_decrypt(encrypted_key)

      content_encryption_key = derive_content_key('Encryption', content_master_key, encryption, digest, aes_length)
      content_integrity_key = derive_content_key('Integrity', content_master_key, encryption, digest, sha_length)

      secured_input = parts.take(4).join('.')
      computed_integrity_value = OpenSSL::HMAC.digest(digest, content_integrity_key, secured_input)
      throw ArgumentError.new('Invalid signature.') unless integrity_value == computed_integrity_value

      cipher = OpenSSL::Cipher.new("AES-#{aes_length}-CBC")
      cipher.decrypt
      cipher.key = content_encryption_key
      cipher.iv = iv
      cipher.update(ciphertext) + cipher.final
    when 'A128GCM', 'A256GCM'
      throw NotImplementedError.new("The GCM family of encryption algorithms are not implemented yet.")
    else
      throw NotImplementedError.new("The #{encryption} encryption algorithm is not supported.")
    end
  end

  private  

  # Derives content keys using the Concat KDF.
  def self.derive_content_key(label, content_master_key, encryption, digest, size)
    round_number = [1].pack('N')
    output_size = [size].pack('N')
    enc_bytes = encryption.encode('utf-8').bytes.to_a.pack('C*')
    epu = epv = [0].pack('N')
    label_bytes = label.encode('us-ascii').bytes.to_a.pack('C*')
    hash_input = round_number + content_master_key + output_size + enc_bytes + epu + epv + label_bytes
    hash = digest.digest(hash_input)
    hash[0..((size / 8) - 1)]
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
  enc = Sandal::Enc::AES128CBC.new(jwe_key.public_key)
  jwe_token = Sandal.encrypt_token(jws_token, enc, { 'cty' => 'JWT' })

  puts jwe_token

  jws_token_2 = Sandal.decrypt_token(jwe_token) { |header| jwe_key }
  roundtrip_claims = Sandal.decode_token(jws_token_2) { |header| Sandal::Sig::RS256.new(jws_key.public_key) }

  puts roundtrip_claims

end