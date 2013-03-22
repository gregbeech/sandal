$:.unshift('.')

require 'base64'
require 'json'
require 'openssl'

require 'sandal/version'
require 'sandal/sig'

# A library for creating and reading JSON Web Tokens (JWT).
module Sandal

  # Creates a signed token.
  def self.encode_token(payload, sig, header_fields = nil)
    if header_fields && header_fields['enc']
      throw ArgumentError.new('The header cannot contain an "enc" parameter.')
    end
    sig ||= Sandal::Sig::None.new

    header = {}
    header['sig'] = sig.name if sig.name != 'none'
    header = header_fields.merge(header) if header_fields

    encoded_header = base64_encode(JSON.generate(header))
    encoded_payload = base64_encode(payload)
    secured_input = [encoded_header, encoded_payload].join('.')

    signature = sig.sign(secured_input)
    encoded_signature = base64_encode(signature)
    [secured_input, encoded_signature].join('.')
  end

  # Creates an encrypted token.
  def self.encrypt_token(header, payload, public_key)
    algorithm = header['alg']
    encryption = header['enc']
    throw ArgumentError.new('The header must contain an "alg" parameter.') unless algorithm
    throw ArgumentError.new('The header must contain an "enc" parameter.') unless encryption
    throw ArgumentError.new('A public key is required.') unless public_key

    encoded_header = base64_encode(JSON.generate(header))

    case encryption 
    when 'A128CBC+HS256', 'A256CBC+HS512'
      aes_length = Integer(encryption[1..3])
      sha_length = Integer(encryption[-3..-1])

      cipher = OpenSSL::Cipher.new("AES-#{aes_length}-CBC")
      cipher.encrypt
      content_master_key = cipher.random_key
      iv = cipher.random_iv

      digest = OpenSSL::Digest.new("SHA#{sha_length}")

      encrypted_key = public_key.public_encrypt(content_master_key)
      encoded_encrypted_key = base64_encode(encrypted_key)
      encoded_iv = base64_encode(iv)

      cipher.key = derive_content_key('Encryption', content_master_key, encryption, digest, aes_length)
      content_integrity_key = derive_content_key('Integrity', content_master_key, encryption, digest, sha_length)

      ciphertext = cipher.update(payload) + cipher.final
      encoded_ciphertext = base64_encode(ciphertext)

      secured_input = [encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext].join('.')
      integrity_value = OpenSSL::HMAC.digest(digest, content_integrity_key, secured_input)
      encoded_integrity_value = base64_encode(integrity_value)

      [secured_input, encoded_integrity_value].join('.')
    when 'A128GCM', 'A256GCM'
      throw NotImplementedError.new("The GCM family of encryption algorithms are not implemented yet.")
    else
      throw NotImplementedError.new("The #{algorithm} encryption algorithm is not supported.")
    end
  end

  # Decodes a token, verifying the signature if present.
  def self.decode_token(token, &key_finder)
    parts = token.split('.')
    throw ArgumentError.new('Invalid token format.') unless [2, 3].include?(parts.length)
    begin
      header = JSON.parse(base64_decode(parts[0]))
      payload = base64_decode(parts[1])
      signature = if parts.length > 2 then base64_decode(parts[2]) else nil end
    rescue
      throw ArgumentError.new('Invalid token encoding.')
    end

    algorithm = header['alg']
    if algorithm && algorithm != 'none'
      throw SecurityError.new('The signature is missing.') unless signature
      case algorithm
      when 'ES256', 'ES384', 'ES512'
        throw NotImplementedError.new('The ES family of signing algorithms are not implemented yet.')
      when 'HS256', 'HS384', 'HS512'
        throw NotImplementedError.new('The HS family of signing algorithms are not implemented yet.')
      when 'RS256', 'RS384', 'RS512'
        throw ArgumentError.new("A key finder is required for the #{algorithm} signing algorithm.") unless key_finder
        public_key = key_finder.call(header)
        throw SecurityError.new('No key was found to verify the signature') unless public_key
        digest = OpenSSL::Digest.new(algorithm.sub('RS', 'SHA'))
        secured_input = parts.take(2).join('.')
        throw ArgumentError.new('Invalid signature.') unless public_key.verify(digest, signature, secured_input)
      else
        throw NotImplementedError.new("The #{algorithm} signing algorithm is not supported.")
      end
    end

    payload
  end

  # Decrypts a token.
  def self.decrypt_token(encrypted_token, &key_finder)
    parts = encrypted_token.split('.')
    throw ArgumentError.new('Invalid token format.') unless parts.length == 5
    begin
      header = JSON.parse(base64_decode(parts[0]))
      encrypted_key = base64_decode(parts[1])
      iv = base64_decode(parts[2])
      ciphertext = base64_decode(parts[3])
      integrity_value = base64_decode(parts[4])
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
      throw NotImplementedError.new("The #{algorithm} encryption algorithm is not supported.")
    end
  end

  private

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

  # sign and encrypt
  jws_key = OpenSSL::PKey::RSA.new(2048)
  sig = Sandal::Sig::RS256.new(jws_key)
  jws_token = Sandal.encode_token(claims.to_s, sig)

  puts jws_token

  jwe_key = OpenSSL::PKey::RSA.new(2048)
  jwe_token = Sandal.encrypt_token({ 'alg' => 'RSA1_5', 'enc' => 'A128CBC+HS256', 'cty' => 'JWT' }, jws_token, jwe_key)

  puts jwe_token

  jws_token_2 = Sandal.decrypt_token(jwe_token) { |header| jwe_key }
  roundtrip_claims = Sandal.decode_token(jws_token_2) { |header| jws_key }

  puts roundtrip_claims

end