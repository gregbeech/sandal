require 'helper'
require 'openssl'

include Sandal::Util

describe Sandal::Enc::Alg::RSA_OAEP do  

  it 'can encrypt and decrypt a content master key' do
    key = OpenSSL::PKey::RSA.new(2048)
    encrypter = Sandal::Enc::Alg::RSA_OAEP.new(key.public_key)
    decrypter = Sandal::Enc::Alg::RSA_OAEP.new(key)
    key = 'an encryption key'
    decrypter.decrypt_key(encrypter.encrypt_key(key)).should == key
  end

  context '#name' do

    it 'is "RSA-OAEP"' do
      alg = Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048))
      alg.name.should == 'RSA-OAEP'
    end

  end

  context '#decrypt_key' do

    it 'can decrypt the encypted content master key from JWE draft-10 section A.1', :jruby_incompatible do
      key = [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252].pack('C*')
      encrypted_key = jwt_base64_decode('ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw')
      alg = Sandal::Enc::Alg::RSA_OAEP.new(SampleKeys.jwe_draft10_a1_rsa)
      alg.decrypt_key(encrypted_key).should == key
    end

    it 'raises a TokenError when the wrong key is used for decryption' do
      key = [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]
      encrypted_key = jwt_base64_decode('ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw')
      alg = Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048))
      expect { alg.decrypt_key(encrypted_key) }.to raise_error Sandal::TokenError, 'Cannot decrypt content key.'
    end

  end

end