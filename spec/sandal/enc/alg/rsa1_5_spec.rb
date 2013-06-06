require "helper"
require "openssl"

include Sandal::Util

describe Sandal::Enc::Alg::RSA1_5 do

  it "can encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = Sandal::Enc::Alg::RSA1_5.new(key.public_key)
    decrypter = Sandal::Enc::Alg::RSA1_5.new(key)
    key = "an encryption key"
    decrypter.decrypt_key(encrypter.encrypt_key(key)).should == key
  end

  it "can use DER-encoded keys to encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = Sandal::Enc::Alg::RSA1_5.new(key.public_key.to_der)
    decrypter = Sandal::Enc::Alg::RSA1_5.new(key.to_der)
    key = "an encryption key"
    decrypter.decrypt_key(encrypter.encrypt_key(key)).should == key
  end

  it "can use PEM-encoded keys to encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = Sandal::Enc::Alg::RSA1_5.new(key.public_key.to_pem)
    decrypter = Sandal::Enc::Alg::RSA1_5.new(key.to_pem)
    key = "an encryption key"
    decrypter.decrypt_key(encrypter.encrypt_key(key)).should == key
  end

  context "#name" do
    it "is 'RSA1_5'" do
      alg = Sandal::Enc::Alg::RSA1_5.new(OpenSSL::PKey::RSA.new(2048))
      alg.name.should == "RSA1_5"
    end
  end

  context "#decrypt_key" do

    it "can decrypt the encypted content master key from JWE draft-11 appendix 2", :jruby_incompatible do
      key = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207].pack("C*")
      encrypted_key = [80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151, 176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181, 156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156, 116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223, 226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66, 212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253, 215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128, 66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199, 54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151, 250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197, 21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102, 166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222, 150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241, 124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242, 16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244, 248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167, 101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169, 146, 114, 165, 204, 71, 136, 41, 252].pack("C*")
      alg = Sandal::Enc::Alg::RSA1_5.new(SampleKeys.jwe_draft11_appendix2_rsa)
      alg.decrypt_key(encrypted_key).should == key
    end

    it "raises an InvalidTokenError when the wrong key is used for decryption" do
      encrypter = Sandal::Enc::Alg::RSA1_5.new(OpenSSL::PKey::RSA.new(2048).public_key)
      decrypter = Sandal::Enc::Alg::RSA1_5.new(OpenSSL::PKey::RSA.new(2048))
      encrypted_key = encrypter.encrypt_key( "an encryption key")
      expect { decrypter.decrypt_key(encrypted_key) }.to raise_error Sandal::InvalidTokenError
    end

  end

end