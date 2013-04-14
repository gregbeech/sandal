require 'helper'
require 'openssl'
require 'securerandom'

# TODO: These tests are really for the Sandal module rather than just the algorithm -- move them!

describe Sandal::Enc::A256CBC_HS512 do

  it 'can encrypt and decrypt tokens with the "dir" algorithm' do
    payload = 'Some text to encrypt'
    content_master_key = SecureRandom.random_bytes(16)

    encrypter = Sandal::Enc::A256CBC_HS512.new(Sandal::Enc::Alg::Direct.new(content_master_key))
    token = Sandal.encrypt_token(payload, encrypter)

    output = Sandal.decrypt_token(token) { encrypter }
    output.should == payload
  end

  it 'can encrypt and decrypt tokens with the RSA1_5 algorithm' do
    payload = 'Some other text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)

    encrypter = Sandal::Enc::A256CBC_HS512.new(Sandal::Enc::Alg::RSA1_5.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)

    output = Sandal.decrypt_token(token) do 
      Sandal::Enc::A256CBC_HS512.new(Sandal::Enc::Alg::RSA1_5.new(rsa))
    end
    output.should == payload
  end

  it 'can encrypt and decrypt tokens with the RSA-OAEP algorithm' do
    payload = 'Some more text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)

    encrypter = Sandal::Enc::A256CBC_HS512.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)

    output = Sandal.decrypt_token(token) do 
      Sandal::Enc::A256CBC_HS512.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa))
    end
    output.should == payload
  end

end

