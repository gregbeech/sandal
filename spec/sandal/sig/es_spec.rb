require "helper"
require "openssl"

include Sandal::Util

# EC isn't implemented in jruby-openssl at the moment
if defined? Sandal::Sig::ES

def make_point(group, x, y)
  group_size = group.curve_name.match(/(\d+)/)[0].to_i
  bn_size = ((group_size + 7) / 8) * 2
  str = "04" + x.to_s(16).rjust(bn_size, "0") + y.to_s(16).rjust(bn_size, "0")
  bn = OpenSSL::BN.new(str, 16)
  OpenSSL::PKey::EC::Point.new(group, bn)
end

shared_examples "signing and validation" do |enc_class|

  it "can sign data and validate signatures" do
    data = "some data to sign"
    group = OpenSSL::PKey::EC::Group.new(enc_class::CURVE_NAME) 
    private_key = OpenSSL::PKey::EC.new(group).generate_key
    signer = enc_class.new(private_key)
    signature = signer.sign(data)
    public_key = OpenSSL::PKey::EC.new(group)
    public_key.public_key = private_key.public_key
    validator = enc_class.new(public_key)
    validator.valid?(signature, data).should == true
  end

  it "can use DER-encoded keys to sign data and validate signatures" do
    data = "some data to sign"
    group = OpenSSL::PKey::EC::Group.new(enc_class::CURVE_NAME) 
    private_key = OpenSSL::PKey::EC.new(group).generate_key
    signer = enc_class.new(private_key.to_der)
    signature = signer.sign(data)
    public_key = OpenSSL::PKey::EC.new(group)
    public_key.public_key = private_key.public_key
    validator = enc_class.new(public_key.to_der)
    validator.valid?(signature, data).should == true
  end

  it "can use PEM-encoded keys to sign data and validate signatures" do
    data = "some data to sign"
    group = OpenSSL::PKey::EC::Group.new(enc_class::CURVE_NAME) 
    private_key = OpenSSL::PKey::EC.new(group).generate_key
    signer = enc_class.new(private_key.to_pem)
    signature = signer.sign(data)
    public_key = OpenSSL::PKey::EC.new(group)
    public_key.public_key = private_key.public_key
    validator = enc_class.new(public_key.to_pem)
    validator.valid?(signature, data).should == true
  end

  context "#initialize" do

    it "raises an argument error if the key has the wrong curve" do
      group = OpenSSL::PKey::EC::Group.new("secp224k1") 
      private_key = OpenSSL::PKey::EC.new(group).generate_key
      expect { enc_class.new(private_key) }.to raise_error ArgumentError
    end

  end

  context "#valid?" do

    it "fails to validate the signature when the key is changed" do 
      data = "some data to sign"
      group = OpenSSL::PKey::EC::Group.new(enc_class::CURVE_NAME) 
      private_key = OpenSSL::PKey::EC.new(group).generate_key
      signer = enc_class.new(private_key)
      signature = signer.sign(data)
      public_key = OpenSSL::PKey::EC.new(group).generate_key
      validator = enc_class.new(public_key)
      validator.valid?(signature, data).should == false
    end

    it "fails to validate the signature when the signature is changed" do 
      data = "some data to sign"
      group = OpenSSL::PKey::EC::Group.new(enc_class::CURVE_NAME) 
      private_key = OpenSSL::PKey::EC.new(group).generate_key
      signer = enc_class.new(private_key)
      signature = signer.sign(data)
      public_key = OpenSSL::PKey::EC.new(group)
      public_key.public_key = private_key.public_key
      validator = enc_class.new(public_key)
      validator.valid?(signature + "x", data).should == false
    end

    it "fails to validate the signature when the data is changed" do 
      data = "some data to sign"
      group = OpenSSL::PKey::EC::Group.new(enc_class::CURVE_NAME) 
      private_key = OpenSSL::PKey::EC.new(group).generate_key
      signer = enc_class.new(private_key)
      signature = signer.sign(data)
      public_key = OpenSSL::PKey::EC.new(group)
      public_key.public_key = private_key.public_key
      validator = enc_class.new(public_key)
      validator.valid?(signature, data + "x").should == false
    end

  end

end

describe Sandal::Sig::ES do

  context "#encode_jws_signature" do

    it "can encode the signature in JWS draft-11 appendix 3" do
      r = make_bn([14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101])
      s = make_bn([197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213])
      signature = Sandal::Sig::ES.encode_jws_signature(r, s, 256)
      base64_signature = jwt_base64_encode(signature)
      base64_signature.should == "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    end

    it "can encode the signature in JWS draft-11 appendix 4" do
      r = make_bn([1, 220, 12, 129, 231, 171, 194, 209, 232, 135, 233, 117, 247, 105, 122, 210, 26, 125, 192, 1, 217, 21, 82, 91, 45, 240, 255, 83, 19, 34, 239, 71, 48, 157, 147, 152, 105, 18, 53, 108, 163, 214, 68, 231, 62, 153, 150, 106, 194, 164, 246, 72, 143, 138, 24, 50, 129, 223, 133, 206, 209, 172, 63, 237, 119, 109])
      s = make_bn([0, 111, 6, 105, 44, 5, 41, 208, 128, 61, 152, 40, 92, 61, 152, 4, 150, 66, 60, 69, 247, 196, 170, 81, 193, 199, 78, 59, 194, 169, 16, 124, 9, 143, 42, 142, 131, 48, 206, 238, 34, 175, 83, 203, 220, 159, 3, 107, 155, 22, 27, 73, 111, 68, 68, 21, 238, 144, 229, 232, 148, 188, 222, 59, 242, 103])
      signature = Sandal::Sig::ES.encode_jws_signature(r, s, 521)
      base64_signature = jwt_base64_encode(signature)
      base64_signature.should == "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
    end

  end

end

describe Sandal::Sig::ES256 do
  include_examples "signing and validation", Sandal::Sig::ES256, "prime256v1"

  context "#name" do
    it "is 'ES256'" do
      enc = Sandal::Sig::ES256.new(OpenSSL::PKey::EC.new("prime256v1").generate_key)
      enc.name.should == "ES256"
    end
  end

  context "#valid?" do

    it "can validate the signature in JWS draft-11 appendix 3" do
      x = make_bn([127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203, 238, 111, 219, 75, 123, 88, 7, 51, 53, 123, 233, 239, 19, 186, 207, 110, 60, 123, 209, 84, 69])
      y = make_bn([199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223, 237, 185, 238, 185, 244, 179, 105, 93, 110, 169, 11, 36, 173, 138, 70, 35, 40, 133, 136, 229, 173])
      d = make_bn([142, 155, 16, 158, 113, 144, 152, 191, 152, 4, 135, 223, 31, 93, 119, 233, 203, 41, 96, 110, 190, 210, 38, 59, 95, 87, 194, 19, 223, 132, 244, 178])
      data = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
      signature = jwt_base64_decode("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")

      group = OpenSSL::PKey::EC::Group.new("prime256v1") 
      public_key = OpenSSL::PKey::EC.new(group)
      public_key.public_key = make_point(group, x, y)
      validator = Sandal::Sig::ES256.new(public_key)
      validator.valid?(signature, data).should == true
    end

  end

end

describe Sandal::Sig::ES384 do
  include_examples "signing and validation", Sandal::Sig::ES384, "secp384r1"

  context "#name" do
    it "is 'ES384'" do
      enc = Sandal::Sig::ES384.new(OpenSSL::PKey::EC.new("secp384r1").generate_key)
      enc.name.should == "ES384"
    end
  end

end

describe Sandal::Sig::ES512 do
  include_examples "signing and validation", Sandal::Sig::ES512, "secp521r1"

  context "#name" do
    it "is 'ES512'" do
      enc = Sandal::Sig::ES512.new(OpenSSL::PKey::EC.new("secp521r1").generate_key)
      enc.name.should == "ES512"
    end
  end

  context "#validate?" do

    it "can validate the signature in JWS draft-11 appendix 4" do
      x = make_bn([1, 233, 41, 5, 15, 18, 79, 198, 188, 85, 199, 213, 57, 51, 101, 223, 157, 239, 74, 176, 194, 44, 178, 87, 152, 249, 52, 235, 4, 227, 198, 186, 227, 112, 26, 87, 167, 145, 14, 157, 129, 191, 54, 49, 89, 232, 235, 203, 21, 93, 99, 73, 244, 189, 182, 204, 248, 169, 76, 92, 89, 199, 170, 193, 1, 164])
      y = make_bn([0, 52, 166, 68, 14, 55, 103, 80, 210, 55, 31, 209, 189, 194, 200, 243, 183, 29, 47, 78, 229, 234, 52, 50, 200, 21, 204, 163, 21, 96, 254, 93, 147, 135, 236, 119, 75, 85, 131, 134, 48, 229, 203, 191, 90, 140, 190, 10, 145, 221, 0, 100, 198, 153, 154, 31, 110, 110, 103, 250, 221, 237, 228, 200, 200, 246])
      d = make_bn([1, 142, 105, 111, 176, 52, 80, 88, 129, 221, 17, 11, 72, 62, 184, 125, 50, 206, 73, 95, 227, 107, 55, 69, 237, 242, 216, 202, 228, 240, 242, 83, 159, 70, 21, 160, 233, 142, 171, 82, 179, 192, 197, 234, 196, 206, 7, 81, 133, 168, 231, 187, 71, 222, 172, 29, 29, 231, 123, 204, 246, 97, 53, 230, 61, 130]  )
      data = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA"
      signature = jwt_base64_decode("AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn")

      group = OpenSSL::PKey::EC::Group.new("secp521r1") 
      public_key = OpenSSL::PKey::EC.new(group)
      public_key.public_key = make_point(group, x, y)
      validator = Sandal::Sig::ES512.new(public_key)
      validator.valid?(signature, data).should == true
    end

  end

end

end