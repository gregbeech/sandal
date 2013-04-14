require 'helper'
require 'openssl'

rsa_private_key = <<KEY_END
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4lt7zb5RlxwLVvw2mOKW06AGrBW3kfUVIkV6lImwqRps6jpZ
UNBOUkLjqIipXBkKeG6TbL46z4Rw2oEcUTTpOgm/9XEiJP/7nfkK/Sr6cChVLDr5
sohKnxkADrltdNwUUF0gPlK0REa2wiEvpd00D46Sfxfa5kpe/oYajCyRtesmGyrD
iD4BKJIaHTal4613l1k8HWhzza4qztbufZ4BMPfHkjyjOBWLsYSU0axI86b5WnxJ
KZUyghxeL51jYqV5eSeMBC3rr+HHuwdF3ulhvDo0jUxGjFJBG/6ZUheVNAGrAvD8
5RV3tp8ukcc02t2l0Z97PWDcZHpiiul+DvvmeQIDAQABAoIBADy56lbiDiWKAojN
lSAi+e/AaMnV8a+YnpjZJu+emORlEH8uNDP4DmsHQug98aGhnit9DtQHnON7VoNo
S96FYWSOpQ8F0PE4M5rH62jMFO/uAhuhnseExPA11swcdv745AJDWZkeuvnuNq2S
FaRb2dGqoCa0kadioGWMOKcOdfDlqcBApTI5IWy67wLJwF7+qTS+BT7BVAreQnQf
2qlYXSPWBxpL8iGobBGXQlsWTdiYDalrfyV0mvJaXxwHml3PMxyVrJyIvbc0HgMn
YqrBgnWrCz7FIU+8OXd4XFGqD09QpHn7SkdLvgXNlSy5fi3SeLN+ClyP1XvrFQYk
KhfCbwECgYEA/CpsxJEZzwCtvBeHlhNvEV5H2O0HI7Wb+pN5J3QyhMjdOc8KZozx
8D3hj6+I2NJM/Uj0V27LH0R92H29fKLjXUjtRwHtrV33PXWQAMzSS8gHOdeQe8iP
GgdAVDdDJsCR3W5oXEQGj7q8QgLAVdV0X9jZ6BG2MGIbdMi6SUE7DlECgYEA5cyY
/diePvEcXsEX8AgraOGwH+E4w+d21uJPjh4UpBhiJdrqEdZ2bjKtpl6czKmqu4tx
R7WNHqRd8LyUpdGHNvQU+kg1Uc1y1hy8HR1x1lZQYMBi4qkB1P6G08RHEL/oilxO
F1EIxYpwHbW/ZVXzGAyIr4Z9xGMLE5j9jVTsg6kCgYB4JdaxSdmcMdyVtDhcH2Ja
Siu9hiJSt2NcXwvo6opvji0qMCXqetmD+FgS2DZB6OHaBPq29gk+GqpDjpXMXugq
OGcl4BtY8V6uH+e/GdhRVztqKfWjpQnaAv55oeMTAcn+UW7UF21w6i5s3Va7Dvtl
97LLyjSelQA0ArgP007KIQKBgQDDzDAPGiK7PnUNxzi+LDfQhXurrhrP0MhRD0L5
tGeh6aS23G/UAwelnUiYGMVBHM98PLOohehX03S3Sfbd0kmDaTT2i8/ig0r1ZEZk
CFKWbbTOux2GQrps4PHAPdzPSLS6LyvachEnP22H4vPRRAp80zEjXVSLoFgvuotP
gKyFAQKBgBuMvB9XVILcn8IcZ3ax9B8agU4jeBLScoBV25GvSq7hUaFaNC4WMHzf
8av7nDTzlZlLLDMB8rvpz66gMWIWGeU5JWYJaiLMM/JeS9UJOo/6Wn10MvtNSBXH
30+kWAHpOSjtxL7tzmMrb46krFS/0iYDFKiLtIPNiacjxlEzBTZL
-----END RSA PRIVATE KEY-----
KEY_END
rsa_public_key = <<KEY_END
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4lt7zb5RlxwLVvw2mOKW
06AGrBW3kfUVIkV6lImwqRps6jpZUNBOUkLjqIipXBkKeG6TbL46z4Rw2oEcUTTp
Ogm/9XEiJP/7nfkK/Sr6cChVLDr5sohKnxkADrltdNwUUF0gPlK0REa2wiEvpd00
D46Sfxfa5kpe/oYajCyRtesmGyrDiD4BKJIaHTal4613l1k8HWhzza4qztbufZ4B
MPfHkjyjOBWLsYSU0axI86b5WnxJKZUyghxeL51jYqV5eSeMBC3rr+HHuwdF3ulh
vDo0jUxGjFJBG/6ZUheVNAGrAvD85RV3tp8ukcc02t2l0Z97PWDcZHpiiul+Dvvm
eQIDAQAB
-----END PUBLIC KEY-----
KEY_END

describe Sandal::Sig::RS256 do

  it 'can sign data and verify signatures' do
    data = 'Hello RS256'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    signer = Sandal::Sig::RS256.new(private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS256.new(private_key.public_key)
    validator.valid?(signature, data).should == true
  end

  it 'can use string keys to sign data and verify signatures' do
    data = 'Hello RS256'
    signer = Sandal::Sig::RS256.new(rsa_private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS256.new(rsa_public_key)
    validator.valid?(signature, data).should == true
  end

end

describe Sandal::Sig::RS384 do

  it 'can sign data and verify signatures' do
    data = 'Hello RS384'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    signer = Sandal::Sig::RS384.new(private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS384.new(private_key.public_key)
    validator.valid?(signature, data).should == true
  end

  it 'can use string keys to sign data and verify signatures' do
    data = 'Hello RS384'
    signer = Sandal::Sig::RS384.new(rsa_private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS384.new(rsa_public_key)
    validator.valid?(signature, data).should == true
  end

end

describe Sandal::Sig::RS512 do
  
  it 'can sign data and verify signatures' do
    data = 'Hello RS512'
    private_key = OpenSSL::PKey::RSA.generate(2048)
    signer = Sandal::Sig::RS512.new(private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS512.new(private_key.public_key)
    validator.valid?(signature, data).should == true
  end

  it 'can use string keys to sign data and verify signatures' do
    data = 'Hello RS512'
    signer = Sandal::Sig::RS512.new(rsa_private_key)
    signature = signer.sign(data)
    validator = Sandal::Sig::RS512.new(rsa_public_key)
    validator.valid?(signature, data).should == true
  end

end