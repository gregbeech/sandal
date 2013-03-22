# require 'helper'
require 'openssl'
require 'base64' # TODO: remove when working

def make_bn(arr)
  hex_str = arr.pack('C*').unpack('H*')[0]
  OpenSSL::BN.new(hex_str, 16)
end

def make_point(group, x, y)
  str = '04' + x.to_s(16) + y.to_s(16)
  bn = OpenSSL::BN.new(str, 16)
  OpenSSL::PKey::EC::Point.new(group, bn)
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

# TODO: This doesn't seem right... :-S
hash = digest.digest(payload)
sig = ec.dsa_sign_asn1(hash) 
