require 'helper'
require 'openssl'
require 'securerandom'

# TODO: These tests are really for the Sandal module rather than just the algorithm -- move them!

if defined? Sandal::Enc::A128GCM

describe Sandal::Enc::A128GCM do

  it 'can encrypt and decrypt tokens with the RSA1_5 algorithm' do
    payload = 'Some other text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)

    encrypter = Sandal::Enc::A128GCM.new(Sandal::Enc::Alg::RSA1_5.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)

    output = Sandal.decrypt_token(token) do 
      Sandal::Enc::A128GCM.new(Sandal::Enc::Alg::RSA1_5.new(rsa))
    end
    output.should == payload
  end

  it 'can encrypt and decrypt tokens with the RSA-OAEP algorithm' do
    payload = 'Some more text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)

    encrypter = Sandal::Enc::A128GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)

    output = Sandal.decrypt_token(token) do 
      Sandal::Enc::A128GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa))
    end
    output.should == payload
  end

end

end