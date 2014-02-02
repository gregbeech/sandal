require "helper"
require "openssl"

shared_examples "signing and validation" do |enc_class|

  it "can sign data and validate signatures" do
    data = "some data to sign"
    key = "A secret key"
    signer = enc_class.new(key)
    signature = signer.sign(data)
    expect(signer.valid?(signature, data)).to eq(true)
  end

  context "#valid?" do

    it "fails to validate the signature when the key is changed" do
      data = "some other data to sign"
      key = "Another secret key"
      signer = enc_class.new(key)
      signature = signer.sign(data)
      verifier = enc_class.new(key + "x")
      expect(verifier.valid?(signature, data)).to eq(false)
    end

    it "fails to validate the signature when the signature is changed" do
      data = "some other data to sign"
      key = "Another secret key"
      signer = enc_class.new(key)
      signature = signer.sign(data)
      expect(signer.valid?(signature + "x", data)).to eq(false)
    end

    it "fails to validate the signature when the data is changed" do
      data = "some other data to sign"
      key = "Another secret key"
      signer = enc_class.new(key)
      signature = signer.sign(data)
      expect(signer.valid?(signature, data + "x")).to eq(false)
    end

  end

end

describe Sandal::Sig::HS256 do
  include_examples "signing and validation", Sandal::Sig::HS256

  context "#name" do
    it "is 'HS256'" do
      enc = Sandal::Sig::HS256.new("any old key")
      expect(enc.name).to eq("HS256")
    end
  end

  it "can validate the signature from JWS dratf-11 appendix 1" do
    data = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    key = [3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163].pack("C*")
    signer = Sandal::Sig::HS256.new(key)
    signature = [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121].pack("C*") 
    expect(signer.valid?(signature, data)).to eq(true)
  end

end

describe Sandal::Sig::HS384 do
  include_examples "signing and validation", Sandal::Sig::HS384

  context "#name" do
    it "is 'HS384'" do
      enc = Sandal::Sig::HS384.new("any old key")
      expect(enc.name).to eq("HS384")
    end
  end

end

describe Sandal::Sig::HS512 do
  include_examples "signing and validation", Sandal::Sig::HS512

  context "#name" do
    it "is 'HS512'" do
      enc = Sandal::Sig::HS512.new("any old key")
      expect(enc.name).to eq("HS512")
    end
  end
  
end