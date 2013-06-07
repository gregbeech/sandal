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

    def test_decrypt_mangled_token(enc_class)
      content_encryption_key = SecureRandom.random_bytes(enc_class::KEY_SIZE / 8)
      enc = enc_class.new(Sandal::Enc::Alg::Direct.new(content_encryption_key))
      token = enc.encrypt("", "any old payload")
      token_parts = token.split(".")
      yield token_parts
      token = token_parts.join(".")
      expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError
    end

    def test_decrypt_token_with_missing_part(enc_class, part_index)
      test_decrypt_mangled_token(enc_class) do |token_parts|
        token_parts.delete_at(part_index)
      end
    end

    it "raises an InvalidTokenError when the header is missing" do
      test_decrypt_token_with_missing_part(enc_class, 0)
    end

    it "raises an InvalidTokenError when the encrypted key is missing" do
      test_decrypt_token_with_missing_part(enc_class, 1)
    end

    it "raises an InvalidTokenError when the IV is missing" do
      test_decrypt_token_with_missing_part(enc_class, 2)
    end

    it "raises an InvalidTokenError when the encrypted data is missing" do
      test_decrypt_token_with_missing_part(enc_class, 3)
    end

    it "raises an InvalidTokenError when the integrity value is missing" do
      test_decrypt_token_with_missing_part(enc_class, 4)
    end

    it "raises an InvalidTokenError when the header value is invalid" do
      test_decrypt_mangled_token(enc_class) do |token_parts|
        token_parts[0] = token_parts[4]
      end
    end

    it "raises an InvalidTokenError when the encrypted key is invalid" do
      test_decrypt_mangled_token(enc_class) do |token_parts|
        token_parts[1] = token_parts[4]
      end
    end

    it "raises an InvalidTokenError when the IV is invalid" do
      test_decrypt_mangled_token(enc_class) do |token_parts|
        token_parts[2] = token_parts[4]
      end
    end

    it "raises an InvalidTokenError when the encrypted data is invalid" do
      test_decrypt_mangled_token(enc_class) do |token_parts|
        token_parts[3] = token_parts[4]
      end
    end

    it "raises an InvalidTokenError when the integrity value is invalid" do
      test_decrypt_mangled_token(enc_class) do |token_parts|
        token_parts[4] = token_parts[0]
      end
    end

  end

end