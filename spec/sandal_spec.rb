require 'helper'
require 'openssl'

describe Sandal do

  it 'encodes and decodes tokens with no signature' do
    payload = 'Hello, World'
    token = Sandal.encode_token(payload, nil)
    decoded_payload = Sandal.decode_token(token)
    decoded_payload.should == payload
  end

  it 'encodes and decodes tokens with "none" signature' do
    payload = 'Hello, World'
    token = Sandal.encode_token(payload, Sandal::Sig::None.instance)
    decoded_payload = Sandal.decode_token(token)
    decoded_payload.should == payload
  end

  it 'decodes non-JSON payloads to a String' do
    token = Sandal.encode_token('not valid json', nil)
    Sandal.decode_token(token).class.should == String
  end

  it 'decodes JSON payloads to a Hash' do
    token = Sandal.encode_token(JSON.generate({ 'valid' => 'json' }), nil)
    Sandal.decode_token(token).class.should == Hash
  end

  it 'raises a token error when the expiry date is far in the past' do
    token = Sandal.encode_token(JSON.generate({ 'exp' => (Time.now - 600).to_i }), nil)
    expect { Sandal.decode_token(token) }.to raise_error Sandal::TokenError
  end

  it 'does not raise an error when the expiry date is far in the past but validation is disabled' do
    token = Sandal.encode_token(JSON.generate({ 'exp' => (Time.now - 600).to_i }), nil)
    Sandal.decode_token(token) { |header, options| options[:validate_exp] = false }
  end

  it 'does not raise an error when the expiry date is in the past but within the clock skew' do
    token = Sandal.encode_token(JSON.generate({ 'exp' => (Time.now - 60).to_i }), nil)
    Sandal.decode_token(token)
  end

  it 'does not raise an error when the expiry date is valid' do
    token = Sandal.encode_token(JSON.generate({ 'exp' => (Time.now + 60).to_i }), nil)
    Sandal.decode_token(token)
  end

  it 'raises a token error when the not-before date is far in the future' do
    token = Sandal.encode_token(JSON.generate({ 'nbf' => (Time.now + 600).to_i }), nil)
    expect { Sandal.decode_token(token) }.to raise_error Sandal::TokenError
  end

  it 'does not raise an error when the not-before date is far in the future but validation is disabled' do
    token = Sandal.encode_token(JSON.generate({ 'nbf' => (Time.now + 600).to_i }), nil)
    Sandal.decode_token(token) { |header, options| options[:validate_nbf] = false }
  end

  it 'does not raise an error when the not-before date is in the future but within the clock skew' do
    token = Sandal.encode_token(JSON.generate({ 'nbf' => (Time.now + 60).to_i }), nil)
    Sandal.decode_token(token)
  end

  it 'does not raise an error when the not-before is valid' do
    token = Sandal.encode_token(JSON.generate({ 'nbf' => (Time.now - 60).to_i }), nil)
    Sandal.decode_token(token)
  end

  it 'encodes and decodes tokens with RS256 signatures' do
    payload = 'Hello RSA256'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(payload, Sandal::Sig::RS256.new(private_key))
    decoded_payload = Sandal.decode_token(token) { |header| Sandal::Sig::RS256.new(private_key.public_key) }
    decoded_payload.should == payload
  end

  it 'encodes and decodes tokens with RS384 signatures' do
    payload = 'Hello RSA384'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(payload, Sandal::Sig::RS384.new(private_key))
    decoded_payload = Sandal.decode_token(token) { |header| Sandal::Sig::RS384.new(private_key.public_key) }
    decoded_payload.should == payload
  end

  it 'encodes and decodes tokens with RS512 signatures' do
    payload = 'Hello RSA512'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(payload, Sandal::Sig::RS512.new(private_key))
    decoded_payload = Sandal.decode_token(token) { |header| Sandal::Sig::RS512.new(private_key.public_key) }
    decoded_payload.should == payload
  end

end