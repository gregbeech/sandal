require "helper"
require "securerandom"

shared_examples "algorithm compatibility" do |enc_class|

  it "can encrypt and decrypt tokens with the dir algorithm" do
    payload = "Some text to encrypt"
    content_encryption_key = SecureRandom.random_bytes(enc_class::KEY_SIZE / 8)
    enc = enc_class.new(Sandal::Enc::Alg::Direct.new(content_encryption_key))
    token = enc.encrypt("", payload)
    output = enc.decrypt(token)
    output.should == payload
  end

  it "can encrypt and decrypt tokens with the RSA1_5 algorithm" do
    payload = "Some other text to encrypt"
    rsa = OpenSSL::PKey::RSA.new(2048)
    encrypter = enc_class.new(Sandal::Enc::Alg::RSA1_5.new(rsa.public_key))
    token = encrypter.encrypt("", payload)
    decrypter = enc_class.new(Sandal::Enc::Alg::RSA1_5.new(rsa))
    output = decrypter.decrypt(token)
    output.should == payload
  end

  it "can encrypt and decrypt tokens with the RSA-OAEP algorithm" do
    payload = "Some more text to encrypt"
    rsa = OpenSSL::PKey::RSA.new(2048)
    encrypter = enc_class.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa.public_key))
    token = encrypter.encrypt("", payload)
    decrypter = enc_class.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa))
    output = decrypter.decrypt(token)
    output.should == payload
  end

end

shared_examples "invalid tokens" do |enc_class|

  context "#decrypt" do

    it "raises an InvalidTokenError when the integrity value is missing" do
      content_encryption_key = SecureRandom.random_bytes(enc_class::KEY_SIZE / 8)
      enc = enc_class.new(Sandal::Enc::Alg::Direct.new(content_encryption_key))
      token = enc.encrypt("", "any old payload")
      token = token.split(".").take(4).join # drop integrity value
      expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError
    end

  end

end