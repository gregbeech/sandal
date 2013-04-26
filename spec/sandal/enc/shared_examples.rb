require 'helper'
require 'securerandom'

shared_examples 'algorithm compatibility' do |enc_class|

  it 'can encrypt and decrypt tokens with the "dir" algorithm' do
    payload = 'Some text to encrypt'
    content_master_key = SecureRandom.random_bytes(32)
    encrypter = enc_class.new(Sandal::Enc::Alg::Direct.new(content_master_key))
    token = Sandal.encrypt_token(payload, encrypter)
    output = Sandal.decode_token(token) { encrypter }
    output.should == payload
  end

  it 'can encrypt and decrypt tokens with the RSA1_5 algorithm' do
    payload = 'Some other text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)
    encrypter = enc_class.new(Sandal::Enc::Alg::RSA1_5.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)
    output = Sandal.decode_token(token) do 
      enc_class.new(Sandal::Enc::Alg::RSA1_5.new(rsa))
    end
    output.should == payload
  end

  it 'can encrypt and decrypt tokens with the RSA-OAEP algorithm' do
    payload = 'Some more text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)
    encrypter = enc_class.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)
    output = Sandal.decode_token(token) do 
      enc_class.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa))
    end
    output.should == payload
  end

end