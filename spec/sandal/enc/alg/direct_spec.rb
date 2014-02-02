require "helper"
require "openssl"

describe Sandal::Enc::Alg::Direct do

  context "#name" do
    it "is 'dir'" do
      alg = Sandal::Enc::Alg::Direct.new("some key")
      expect(alg.name).to eq("dir")
    end
  end

  context "#preshared_key" do
    it "returns the pre-shared key" do
      key = "the pre-shared key"
      alg = Sandal::Enc::Alg::Direct.new(key)
      expect(alg.preshared_key).to eq(key)
    end
  end

  context "#encrypt_key" do
    it "returns an empty string" do
      alg = Sandal::Enc::Alg::Direct.new("the real key")
      expect(alg.encrypt_key("any value")).to eq("")
    end
  end

  context "#decrypt_key" do

    it "returns the pre-shared content key when the value to decrypt is nil" do
      key = "a pre-shared key"
      alg = Sandal::Enc::Alg::Direct.new(key)
      expect(alg.decrypt_key(nil)).to eq(key)
    end

    it "returns the pre-shared content key when the value to decrypt is empty" do
      key = "my pre-shared key"
      alg = Sandal::Enc::Alg::Direct.new(key)
      expect(alg.decrypt_key("")).to eq(key)
    end

    it "raises an InvalidTokenError if the value to decrypt is not nil or empty" do
      alg = Sandal::Enc::Alg::Direct.new("the pre-shared key")
      expect { alg.decrypt_key("a value") }.to raise_error Sandal::InvalidTokenError
    end

  end

end