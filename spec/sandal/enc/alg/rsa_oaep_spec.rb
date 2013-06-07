require "helper"
require "openssl"

include Sandal::Util

describe Sandal::Enc::Alg::RSA_OAEP do  

  it "can encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = Sandal::Enc::Alg::RSA_OAEP.new(key.public_key)
    decrypter = Sandal::Enc::Alg::RSA_OAEP.new(key)
    key = "an encryption key"
    decrypter.decrypt_key(encrypter.encrypt_key(key)).should == key
  end

  it "can use DER-encoded keys to encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = Sandal::Enc::Alg::RSA_OAEP.new(key.public_key.to_der)
    decrypter = Sandal::Enc::Alg::RSA_OAEP.new(key.to_der)
    key = "an encryption key"
    decrypter.decrypt_key(encrypter.encrypt_key(key)).should == key
  end

  it "can use PEM-encoded keys to encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = Sandal::Enc::Alg::RSA_OAEP.new(key.public_key.to_pem)
    decrypter = Sandal::Enc::Alg::RSA_OAEP.new(key.to_pem)
    key = "an encryption key"
    decrypter.decrypt_key(encrypter.encrypt_key(key)).should == key
  end

  context "#name" do
    it "is 'RSA-OAEP'" do
      alg = Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048))
      alg.name.should == "RSA-OAEP"
    end
  end

  context "#decrypt_key" do

    it "can decrypt the encypted content master key from JWE draft-11 appendix 1", :jruby_incompatible do
      key = [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252].pack("C*")
      encrypted_key = [56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203, 22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216, 82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220, 145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214, 74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182, 13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228, 173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158, 89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138, 243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6, 41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126, 215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58, 63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98, 193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215, 206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216, 104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197, 89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219, 172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134, 117, 114, 135, 206].pack("C*")
      alg = Sandal::Enc::Alg::RSA_OAEP.new(SampleKeys.jwe_draft11_appendix1_rsa)
      alg.decrypt_key(encrypted_key).should == key
    end

    it "raises a InvalidTokenError when the wrong key is used for decryption" do
      encrypter = Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048).public_key)
      decrypter = Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048))
      encrypted_key = encrypter.encrypt_key( "an encryption key")
      expect { decrypter.decrypt_key(encrypted_key) }.to raise_error Sandal::InvalidTokenError
    end

  end

end