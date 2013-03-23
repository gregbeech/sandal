# require 'helper'
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

def asn1_decode(signature)
  asn1 = OpenSSL::ASN1.decode(signature)
  return asn1.value[0].value, asn1.value[1].value
end

def asn1_encode(r, s)
  items = [OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]
  OpenSSL::ASN1::Sequence.new(items).to_der
end

# JWS A3.1 example
x = make_bn([127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203, 238, 111, 219, 75, 123, 88, 7, 51, 53, 123, 233, 239, 19, 186, 207, 110, 60, 123, 209, 84, 69])
y = make_bn([199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223, 237, 185, 238, 185, 244, 179, 105, 93, 110, 169, 11, 36, 173, 138, 70, 35, 40, 133, 136, 229, 173])
d = make_bn([142, 155, 16, 158, 113, 144, 152, 191, 152, 4, 135, 223, 31, 93, 119, 233, 203, 41, 96, 110, 190, 210, 38, 59, 95, 87, 194, 19, 223, 132, 244, 178])

group = OpenSSL::PKey::EC::Group.new('prime256v1') # also: secp384r1, secp521r1
point = make_point(group, x, y)

ec = OpenSSL::PKey::EC.new(group)
ec.public_key = point
ec.private_key = d

digest = OpenSSL::Digest::SHA256.new
payload = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'

hash = digest.digest(payload)
signature = ec.dsa_sign_asn1(hash)
r, s = asn1_decode(signature)
enc_sig = [r.to_s(16) + s.to_s(16)].pack('H*')
p enc_sig
r = OpenSSL::BN.new(enc_sig[0..31].unpack('H*')[0], 16)
s = OpenSSL::BN.new(enc_sig[32..64].unpack('H*')[0], 16)


p ec.dsa_verify_asn1(hash, asn1_encode(r, s))

# p [r.to_s(16)].pack('H*')

# also check the points from the example verify as expected
# r = make_bn([14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101]  )
# s = make_bn([197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213])

# p [r.to_s(16) + s.to_s(16)].pack('H*').unpack('C*')

# p ec.dsa_verify_asn1(hash, asn1_encode(r, s))




