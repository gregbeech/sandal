require 'helper'
require 'openssl'

def make_bn(arr)
  hex_str = arr.pack('C*').unpack('H*')[0]
  OpenSSL::BN.new(hex_str, 16)
end

def make_point(group, x, y)
  str = '04' + x.to_s(16) + y.to_s(16)
  bn = OpenSSL::BN.new(str, 16)
  OpenSSL::PKey::EC::Point.new(group, bn)
end

describe Sandal::Sig::ES256 do

  it 'can sign data and verify signatures' do
    group = OpenSSL::PKey::EC::Group.new('prime256v1') 
    private_key = OpenSSL::PKey::EC.new(group).generate_key
    data = 'Hello ES256'
    signer = Sandal::Sig::ES256.new(private_key)
    signature = signer.sign(data)
    public_key = OpenSSL::PKey::EC.new(group)
    public_key.public_key = private_key.public_key
    verifier = Sandal::Sig::ES256.new(public_key)
    verifier.verify(signature, data).should == true
  end

  it 'can verify the signature in JWS section A3.1' do
    x = make_bn([127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203, 238, 111, 219, 75, 123, 88, 7, 51, 53, 123, 233, 239, 19, 186, 207, 110, 60, 123, 209, 84, 69])
    y = make_bn([199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223, 237, 185, 238, 185, 244, 179, 105, 93, 110, 169, 11, 36, 173, 138, 70, 35, 40, 133, 136, 229, 173])
    d = make_bn([142, 155, 16, 158, 113, 144, 152, 191, 152, 4, 135, 223, 31, 93, 119, 233, 203, 41, 96, 110, 190, 210, 38, 59, 95, 87, 194, 19, 223, 132, 244, 178])
    r = make_bn([14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101]  )
    s = make_bn([197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213])
    data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    signature = Sandal::Sig::ES.encode_jws_signature(r, s)

    group = OpenSSL::PKey::EC::Group.new('prime256v1') 
    public_key = OpenSSL::PKey::EC.new(group)
    public_key.public_key = make_point(group, x, y)
    verifier = Sandal::Sig::ES256.new(public_key)
    verifier.verify(signature, data).should == true
  end

end

describe Sandal::Sig::ES384 do
  it 'can sign data and verify signatures' do
    group = OpenSSL::PKey::EC::Group.new('secp384r1') 
    private_key = OpenSSL::PKey::EC.new(group).generate_key
    data = 'Hello ES384'
    signer = Sandal::Sig::ES384.new(private_key)
    signature = signer.sign(data)
    public_key = OpenSSL::PKey::EC.new(group)
    public_key.public_key = private_key.public_key
    verifier = Sandal::Sig::ES384.new(public_key)
    verifier.verify(signature, data).should == true
  end
end

describe Sandal::Sig::ES512 do
  it 'can sign data and verify signatures' do
    group = OpenSSL::PKey::EC::Group.new('secp521r1') 
    private_key = OpenSSL::PKey::EC.new(group).generate_key
    data = 'Hello ES512'
    signer = Sandal::Sig::ES512.new(private_key)
    signature = signer.sign(data)
    public_key = OpenSSL::PKey::EC.new(group)
    public_key.public_key = private_key.public_key
    verifier = Sandal::Sig::ES512.new(public_key)
    verifier.verify(signature, data).should == true
  end
end