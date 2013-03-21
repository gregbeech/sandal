require 'helper'
require 'openssl'

describe Sandal do

  it 'encodes and decodes tokens with no signature' do
    header = {}
    payload = 'Hello, World'
    token = Sandal.encode_token(header, payload)
    decoded_payload = Sandal.decode_token(token)
    decoded_payload.should == payload
  end

  it 'encodes and decodes tokens with RS256 signatures' do
    header = { 'alg' => 'RS256' }
    payload = 'Hello RSA'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(header, payload, private_key)
    decoded_payload = Sandal.decode_token(token) { |header| private_key.public_key }
    decoded_payload.should == payload
  end

  it 'encodes and decodes tokens with RS384 signatures' do
    header = { 'alg' => 'RS384' }
    payload = 'Hello RSA'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(header, payload, private_key)
    decoded_payload = Sandal.decode_token(token) { |header| private_key.public_key }
    decoded_payload.should == payload
  end

  it 'encodes and decodes tokens with RS512 signatures' do
    header = { 'alg' => 'RS512' }
    payload = 'Hello RSA'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encode_token(header, payload, private_key)
    decoded_payload = Sandal.decode_token(token) { |header| private_key.public_key }
    decoded_payload.should == payload
  end

  it 'encrypts and decrypts tokens with A128CBC+HS256 encryption and RSA1_5 key encryption' do
    header = { 'alg' => 'RSA1_5', 'enc' => 'A128CBC+HS256' }
    payload = 'Hello AES/HMAC'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encrypt_token(header, payload, private_key.public_key)
    decrypted_payload = Sandal.decrypt_token(token) { |header| private_key }
    decrypted_payload.should == payload
  end

  it 'encrypts and decrypts tokens with A256CBC+HS512 encryption and RSA1_5 key encryption' do
    header = { 'alg' => 'RSA1_5', 'enc' => 'A256CBC+HS512' }
    payload = 'Hello AES/HMAC'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    token = Sandal.encrypt_token(header, payload, private_key.public_key)
    decrypted_payload = Sandal.decrypt_token(token) { |header| private_key }
    decrypted_payload.should == payload
  end

end