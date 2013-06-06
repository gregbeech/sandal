require "helper"
require "openssl"

shared_examples "signing and validation" do |enc_class|

  it "can sign data and validate signatures" do
    data = "this is my data"
    private_key = OpenSSL::PKey::RSA.generate(2048)
    signer = Sandal::Sig::RS384.new(private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS384.new(private_key.public_key)
    validator.valid?(signature, data).should == true
  end

  it "can use DER-encoded keys to sign data and validate signatures" do
    data = "there are many like it"
    private_key = OpenSSL::PKey::RSA.generate(2048)
    signer = Sandal::Sig::RS384.new(private_key.to_der)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS384.new(private_key.public_key.to_der)
    validator.valid?(signature, data).should == true
  end

  it "can use PEM-encoded keys to sign data and validate signatures" do
    data = "but this one is mine"
    private_key = OpenSSL::PKey::RSA.generate(2048)
    signer = Sandal::Sig::RS384.new(private_key.to_pem)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS384.new(private_key.public_key.to_pem)
    validator.valid?(signature, data).should == true
  end

  context "#valid?" do

    it "fails to validate the signature when the key is changed" do
      data = "this is my data"
      signer = Sandal::Sig::RS384.new(OpenSSL::PKey::RSA.generate(2048))
      signature = signer.sign(data)
      validator = Sandal::Sig::RS384.new(OpenSSL::PKey::RSA.generate(2048).public_key)
      validator.valid?(signature, data).should == false
    end

    it "fails to validate the signature when the signature is changed" do
      data = "this is my data"
      private_key = OpenSSL::PKey::RSA.generate(2048)
      signer = Sandal::Sig::RS384.new(private_key)
      signature = signer.sign(data)
      validator = Sandal::Sig::RS384.new(private_key.public_key)
      validator.valid?(signature + "x", data).should == false
    end

    it "fails to validate the signature when the data is changed" do
      data = "this is my data"
      private_key = OpenSSL::PKey::RSA.generate(2048)
      signer = Sandal::Sig::RS384.new(private_key)
      signature = signer.sign(data)
      validator = Sandal::Sig::RS384.new(private_key.public_key)
      validator.valid?(signature, data + "x").should == false
    end

  end

end


describe Sandal::Sig::RS256 do
  include_examples "signing and validation", Sandal::Sig::RS256

  it "can validate the signature from JWS dratf-11 appendix 2" do
    data = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    private_key = SampleKeys.jws_draft11_appendix2_rsa
    signer = Sandal::Sig::RS384.new(private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS384.new(private_key.public_key)
    validator.valid?(signature, data).should == true
  end 

  context "#name" do
    it "is 'RS256'" do
      enc = Sandal::Sig::RS256.new(OpenSSL::PKey::RSA.generate(2048))
      enc.name.should == "RS256"
    end
  end

end

describe Sandal::Sig::RS384 do
  include_examples "signing and validation", Sandal::Sig::RS384

  context "#name" do
    it "is 'RS384'" do
      enc = Sandal::Sig::RS384.new(OpenSSL::PKey::RSA.generate(2048))
      enc.name.should == "RS384"
    end
  end

end

describe Sandal::Sig::RS512 do
  include_examples "signing and validation", Sandal::Sig::RS512

  context "#name" do
    it "is 'RS512'" do
      enc = Sandal::Sig::RS512.new(OpenSSL::PKey::RSA.generate(2048))
      enc.name.should == "RS512"
    end
  end
  
end