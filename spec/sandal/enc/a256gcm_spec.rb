require 'helper'
require 'openssl'
require_relative 'shared_examples'

if defined? Sandal::Enc::A256GCM

describe Sandal::Enc::A256GCM do
  include_examples 'algorithm compatibility', Sandal::Enc::A256GCM

  context '#name' do

    it 'is "A256GCM"' do
      enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::Direct.new('a cmk'))
      enc.name.should == 'A256GCM'
    end

  end

  context '#decrypt' do

    it 'can decrypt the example token from JWE draft-10 section A.1', :jruby_incompatible do
      token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.ghEgxninkHEAMp4xZtB2mA'
      enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(SampleKeys.jwe_draft10_a1_rsa))
      enc.decrypt(token).should == 'The true sign of intelligence is not knowledge but imagination.'
    end

    it 'raises an InvalidTokenError when the integrity value is changed', :jruby_incompatible do
      token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.7V5ZDko0v_mf2PAc4JMiUg'
      enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(SampleKeys.jwe_draft10_a1_rsa))
      expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError, 'Cannot decrypt token.'
    end

    it 'raises an InvalidTokenError when the wrong key is used for decryption' do
      token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.ghEgxninkHEAMp4xZtB2mA'
      enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048)))
      expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError, 'Cannot decrypt content key.'
    end

    it 'raises an InvalidTokenError when the token has an invalid format' do
      token = 'not.a.valid.token.format'
      enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::Direct.new('a cmk'))
      expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError, 'Invalid token encoding.'
    end

  end

end

end