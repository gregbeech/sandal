require 'helper'
require 'openssl'

describe Sandal::Enc::AES128CBC_HS256 do

  it 'rocks' do
    data = 'Hello HS256'
    key = 'A secret key'

    alg = Sandal::Enc::Alg::Direct.new(OpenSSL::Cipher.new('aes-128-cbc').random_key)
    encrypter = Sandal::Enc::AES128CBC_HS256.new(alg)
    enc = Sandal.encrypt_token('hello world', encrypter)

    puts enc
  end

  it 'rocks more' do
    data = 'Hello HS256'
    key = 'A secret key'

    alg = Sandal::Enc::Alg::RSA1_5.new(OpenSSL::PKey::RSA.new(2096))
    encrypter = Sandal::Enc::AES128CBC_HS256.new(alg)
    enc = Sandal.encrypt_token('hello world', encrypter)

    puts enc
  end

  it 'rocks even more' do
    data = 'Hello HS256'
    key = 'A secret key'

    alg = Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2096))
    encrypter = Sandal::Enc::AES128CBC_HS256.new(alg)
    enc = Sandal.encrypt_token('hello world', encrypter)

    puts enc
  end


end