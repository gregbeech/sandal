require 'helper'
require 'openssl'

describe Sandal do

  it 'encodes and decodes tokens with a nil signature' do
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