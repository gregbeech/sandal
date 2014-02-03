require 'helper'
require 'openssl'
require 'multi_json'

describe Sandal do

  context '#encrypt_token' do

    it 'supports zip using the DEFLATE algorithm' do
      payload = 'some payload to be zipped'
      private_key = OpenSSL::PKey::RSA.new(2048)
      encrypter = Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::RSA1_5.new(private_key.public_key))
      token = Sandal.encrypt_token(payload, encrypter, { 'zip' => 'DEF' })
      decoded_payload = Sandal.decode_token(token) do |header|
        Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::RSA1_5.new(private_key))
      end
      expect(decoded_payload).to eq(payload)
    end

    it 'raises an ArgumentError if the zip parameter is present and nil' do
      encrypter = Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::RSA1_5.new(OpenSSL::PKey::RSA.new(2048)))
      expect {
        Sandal.encrypt_token('any payload', encrypter, { 'zip' => nil })
      }.to raise_error ArgumentError, 'Invalid zip algorithm.'
    end

    it 'raises an ArgumentError if the zip parameter is present and not "DEF"' do
      encrypter = Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::RSA1_5.new(OpenSSL::PKey::RSA.new(2048)))
      expect {
        Sandal.encrypt_token('any payload', encrypter, { 'zip' => 'INVALID' })
      }.to raise_error ArgumentError, 'Invalid zip algorithm.'
    end

  end

  it 'raises a token error when the token format is invalid' do
    expect { Sandal.decode_token('not a valid token') }.to raise_error Sandal::TokenError
  end

  it 'raises a token error when the token encoding is invalid' do
    expect { Sandal.decode_token('an.invalid.token') }.to raise_error Sandal::TokenError
  end

  it 'encodes and decodes tokens with no signature' do
    payload = 'Hello, World'
    token = Sandal.encode_token(payload, nil)
    decoded_payload = Sandal.decode_token(token)
    expect(decoded_payload).to eq(payload)
  end

  it 'encodes and decodes tokens with "none" signature' do
    payload = 'Hello, World'
    token = Sandal.encode_token(payload, Sandal::Sig::None.instance)
    decoded_payload = Sandal.decode_token(token)
    expect(decoded_payload).to eq(payload)
  end

  it 'decodes non-JSON payloads to a String' do
    token = Sandal.encode_token('not valid json', nil)
    expect(Sandal.decode_token(token)).to be_kind_of String
  end

  it 'decodes JSON payloads to a Hash' do
    token = Sandal.encode_token({ 'valid' => 'json' }, nil)
    expect(Sandal.decode_token(token)).to be_kind_of Hash
  end

  it 'raises a claim error when the expiry date is far in the past' do
    token = Sandal.encode_token({ 'exp' => (Time.now - 600).to_i }, nil)
    expect { Sandal.decode_token(token) }.to raise_error Sandal::ClaimError
  end

  it 'raises a claim error when the expiry date is invalid' do
    token = Sandal.encode_token({ 'exp' => 'invalid value' }, nil)
    expect { Sandal.decode_token(token) }.to raise_error Sandal::ClaimError
  end

  it 'does not raise an error when the expiry date is in the past but validation is disabled' do
    token = Sandal.encode_token({ 'exp' => (Time.now - 600).to_i }, nil)
    Sandal.decode_token(token) do |header, options|
      options[:ignore_exp] = true
      nil
    end
  end

  it 'does not raise an error when the expiry date is in the past but within the clock skew' do
    token = Sandal.encode_token({ 'exp' => (Time.now - 60).to_i }, nil)
    Sandal.decode_token(token) do |header, options|
      options[:max_clock_skew] = 300
      nil
    end
  end

  it 'does not raise an error when the expiry date is valid' do
    token = Sandal.encode_token({ 'exp' => (Time.now + 60).to_i }, nil)
    Sandal.decode_token(token)
  end

  it 'raises a claim error when the not-before date is far in the future' do
    token = Sandal.encode_token({ 'nbf' => (Time.now + 600).to_i }, nil)
    expect { Sandal.decode_token(token) }.to raise_error Sandal::ClaimError
  end

  it 'raises a claim error when the not-before date is invalid' do
    token = Sandal.encode_token({ 'nbf' => 'invalid value' }, nil)
    expect { Sandal.decode_token(token) }.to raise_error Sandal::ClaimError
  end

  it 'does not raise an error when the not-before date is in the future but validation is disabled' do
    token = Sandal.encode_token({ 'nbf' => (Time.now + 600).to_i }, nil)
    Sandal.decode_token(token) do |header, options|
      options[:ignore_nbf] = true
      nil
    end
  end

  it 'does not raise an error when the not-before date is in the future but within the clock skew' do
    token = Sandal.encode_token({ 'nbf' => (Time.now + 60).to_i }, nil)
    Sandal.decode_token(token) do |header, options|
      options[:max_clock_skew] = 300
      nil
    end
  end

  it 'does not raise an error when the not-before is valid' do
    token = Sandal.encode_token({ 'nbf' => (Time.now - 60).to_i }, nil)
    Sandal.decode_token(token)
  end

  it 'raises a claim error when the issuer is not valid' do
    token = Sandal.encode_token({ 'iss' => 'example.org' }, nil)
    expect { Sandal.decode_token(token) do |header, options|
      options[:valid_iss] = ['example.net']
      nil
    end }.to raise_error Sandal::ClaimError
  end

  it 'does not raise an error when the issuer is valid' do
    token = Sandal.encode_token({ 'iss' => 'example.org' }, nil)
    Sandal.decode_token(token) do |header, options|
      options[:valid_iss] = ['example.org', 'example.com']
      nil
    end
  end

  it 'raises a claim error when the audience string is not valid' do
    token = Sandal.encode_token({ 'aud' => 'example.com' }, nil)
    expect { Sandal.decode_token(token) do |header, options|
      options[:valid_aud] = ['example.net']
      nil
    end }.to raise_error Sandal::ClaimError
  end

  it 'raises a claim error when the audience array is not valid' do
    token = Sandal.encode_token({ 'aud' => ['example.org', 'example.com'] }, nil)
    expect { Sandal.decode_token(token) do |header, options|
      options[:valid_aud] = ['example.net']
      nil
    end }.to raise_error Sandal::ClaimError
  end

  it 'does not raise an error when the audience string is valid' do
    token = Sandal.encode_token({ 'aud' => 'example.net' }, nil)
    Sandal.decode_token(token) do |header, options|
      options[:valid_aud] = ['example.net']
      nil
    end
  end

  it 'does not raise an error when the audience array is valid' do
    token = Sandal.encode_token({ 'aud' => ['example.com', 'example.net'] }, nil)
    Sandal.decode_token(token) do |header, options|
      options[:valid_aud] = ['example.net']
      nil
    end
  end

  it 'encodes and decodes tokens with RS256 signatures' do
    payload = 'Hello RSA256'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(payload, Sandal::Sig::RS256.new(private_key))
    decoded_payload = Sandal.decode_token(token) { |header| Sandal::Sig::RS256.new(private_key.public_key) }
    expect(decoded_payload).to eq(payload)
  end

  it 'encodes and decodes tokens with RS384 signatures' do
    payload = 'Hello RSA384'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(payload, Sandal::Sig::RS384.new(private_key))
    decoded_payload = Sandal.decode_token(token) { |header| Sandal::Sig::RS384.new(private_key.public_key) }
    expect(decoded_payload).to eq(payload)
  end

  it 'encodes and decodes tokens with RS512 signatures' do
    payload = 'Hello RSA512'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(payload, Sandal::Sig::RS512.new(private_key))
    decoded_payload = Sandal.decode_token(token) { |header| Sandal::Sig::RS512.new(private_key.public_key) }
    expect(decoded_payload).to eq(payload)
  end

end