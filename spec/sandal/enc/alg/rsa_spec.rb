require "helper"
require "openssl"

shared_examples "encryption and decryption" do |enc_class|

  it "can encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = enc_class.new(key.public_key)
    decrypter = enc_class.new(key)
    key = "an encryption key"
    expect(decrypter.decrypt_key(encrypter.encrypt_key(key))).to eq(key)
  end

  it "can use DER-encoded keys to encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = enc_class.new(key.public_key.to_der)
    decrypter = enc_class.new(key.to_der)
    key = "an encryption key"
    expect(decrypter.decrypt_key(encrypter.encrypt_key(key))).to eq(key)
  end

  it "can use PEM-encoded keys to encrypt and decrypt a content master key" do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = enc_class.new(key.public_key.to_pem)
    decrypter = enc_class.new(key.to_pem)
    key = "an encryption key"
    expect(decrypter.decrypt_key(encrypter.encrypt_key(key))).to eq(key)
  end

  context "#decrypt_key" do

    it "raises an InvalidTokenError when the wrong key is used for decryption" do
      encrypter = enc_class.new(OpenSSL::PKey::RSA.new(2048).public_key)
      decrypter = enc_class.new(OpenSSL::PKey::RSA.new(2048))
      encrypted_key = encrypter.encrypt_key("an encryption key")
      expect { decrypter.decrypt_key(encrypted_key) }.to raise_error Sandal::InvalidTokenError
    end

    it "raises an InvalidTokenError when the key to decrypt is nil" do
      decrypter = enc_class.new(OpenSSL::PKey::RSA.new(2048))
      expect { decrypter.decrypt_key(nil) }.to raise_error Sandal::InvalidTokenError
    end

    it "raises an InvalidTokenError when the key to decrypt is empty" do
      decrypter = enc_class.new(OpenSSL::PKey::RSA.new(2048))
      expect { decrypter.decrypt_key("") }.to raise_error Sandal::InvalidTokenError
    end

    it "raises an InvalidTokenError when the key to decrypt is invalid" do
      decrypter = enc_class.new(OpenSSL::PKey::RSA.new(2048))
      expect { decrypter.decrypt_key("not a real encrypted key") }.to raise_error Sandal::InvalidTokenError
    end

  end

end

describe Sandal::Enc::Alg::RSA1_5 do
  include_examples "encryption and decryption", Sandal::Enc::Alg::RSA1_5

  context "#name" do
    it "is 'RSA1_5'" do
      alg = Sandal::Enc::Alg::RSA1_5.new(OpenSSL::PKey::RSA.new(2048))
      expect(alg.name).to eq("RSA1_5")
    end
  end

  context "#decrypt_key" do
    it "can decrypt the encypted content master key from JWE draft-11 appendix 2", :jruby_incompatible do
      key = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207].pack("C*")
      encrypted_key = [80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151, 176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181, 156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156, 116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223, 226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66, 212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253, 215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128, 66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199, 54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151, 250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197, 21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102, 166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222, 150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241, 124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242, 16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244, 248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167, 101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169, 146, 114, 165, 204, 71, 136, 41, 252].pack("C*")
      alg = Sandal::Enc::Alg::RSA1_5.new(SampleKeys.jwe_draft11_appendix2_rsa)
      expect(alg.decrypt_key(encrypted_key)).to eq(key)
    end
  end

end

describe Sandal::Enc::Alg::RSA_OAEP do
  include_examples "encryption and decryption", Sandal::Enc::Alg::RSA_OAEP

  context "#name" do
    it "is 'RSA-OAEP'" do
      alg = Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048))
      expect(alg.name).to eq("RSA-OAEP")
    end
  end

  context "#decrypt_key" do
    it "can decrypt the encypted content master key from JWE draft-11 appendix 1", :jruby_incompatible do
      key = [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252].pack("C*")
      encrypted_key = [56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203, 22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216, 82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220, 145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214, 74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182, 13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228, 173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158, 89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138, 243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6, 41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126, 215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58, 63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98, 193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215, 206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216, 104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197, 89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219, 172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134, 117, 114, 135, 206].pack("C*")
      alg = Sandal::Enc::Alg::RSA_OAEP.new(SampleKeys.jwe_draft11_appendix1_rsa)
      expect(alg.decrypt_key(encrypted_key)).to eq(key)
    end
  end

end