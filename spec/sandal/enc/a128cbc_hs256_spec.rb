require 'helper'
require 'openssl'
require_relative 'shared_examples'

# TODO: These tests are really for the Sandal module rather than just the algorithm -- move them!

describe Sandal::Enc::A128CBC_HS256 do
  include_examples 'algorithm compatibility', Sandal::Enc::A128CBC_HS256

  context '#name' do

    it 'is "A128CBC-HS256"' do
      enc = Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::Direct.new('a cmk'))
      enc.name.should == 'A128CBC-HS256'
    end

  end

  context '#decrypt' do

    it 'can decrypt the example token from JWE draft-10 section A.2', :jruby_incompatible do
      token = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.nJa_uE2D0wlKz-OcwSbKFzj302xYSI-RLBM6hbVGmP4axtJQPA9S0po3s3NMkmOmkkawnfwPNjpc0mc3z79cuQWkQPFQo-mDxmogz8dxBcheaTUg3ZvpbGCXxZjDYENRWiZ5M9BiLy09BIF5mHp85QL6XED1JEZMOh-1uT1lqPDcDD79qWtrCfEJmNmfsx5fcB2PfAcVtQ0t_YmOXx5_Gu0it1nILKXLR2Ynf9mfLhEcC5LebpWyEHW6WzQ4iH9SIcIupPV1iKCzmJcPrDBJ5Fc_KMBcXBinaS__wftNywaGgfi_NSsx24LxtK6fIkejRlMBmCfxv0Tg8CtxpURigg.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.fY2U_Hx5VcfXmipEldHhMA'
      enc = Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::RSA1_5.new(SampleKeys.jwe_draft10_a2_rsa))
      enc.decrypt(token).should == 'Live long and prosper.'
    end

    # it 'raises an InvalidTokenError when the integrity value is changed', :jruby_incompatible do
    #   token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ApfOLCaDbqs_JXPYy2I937v§_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.7V5ZDko0v_mf2PAc4JMiUg'
    #   enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(SampleKeys.jwe_draft10_a1_rsa))
    #   expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError, 'Cannot decrypt token.'
    # end

    # it 'raises an InvalidTokenError when the wrong key is used for decryption' do
    #   token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.ghEgxninkHEAMp4xZtB2mA'
    #   enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(OpenSSL::PKey::RSA.new(2048)))
    #   expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError, 'Cannot decrypt content master key.'
    # end

    # it 'raises an InvalidTokenError when the token has an invalid format' do
    #   token = 'not.a.valid.token.format'
    #   enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::Direct.new('a cmk'))
    #   expect { enc.decrypt(token) }.to raise_error Sandal::InvalidTokenError, 'Invalid token encoding.'
    # end

  end

  # # these tests don't run with jruby as it errors when you try and set rsa.d parameter directly
  # context 'using the example RSA key from JWE section A.2', :jruby_incompatible do

  #   before :all do
  #     @rsa = OpenSSL::PKey::RSA.new(2048)
  #     @rsa.n = make_bn([177, 119, 33, 13, 164, 30, 108, 121, 207, 136, 107, 242, 12, 224, 19, 226, 198, 134, 17, 71, 173, 75, 42, 61, 48, 162, 206, 161, 97, 108, 185, 234, 226, 219, 118, 206, 118, 5, 169, 224, 60, 181, 90, 85, 51, 123, 6, 224, 4, 122, 29, 230, 151, 12, 244, 127, 121, 25, 4, 85, 220, 144, 215, 110, 130, 17, 68, 228, 129, 138, 7, 130, 231, 40, 212, 214, 17, 179, 28, 124, 151, 178, 207, 20, 14, 154, 222, 113, 176, 24, 198, 73, 211, 113, 9, 33, 178, 80, 13, 25, 21, 25, 153, 212, 206, 67, 154, 147, 70, 194, 192, 183, 160, 83, 98, 236, 175, 85, 23, 97, 75, 199, 177, 73, 145, 50, 253, 206, 32, 179, 254, 236, 190, 82, 73, 67, 129, 253, 252, 220, 108, 136, 138, 11, 192, 1, 36, 239, 228, 55, 81, 113, 17, 25, 140, 63, 239, 146, 3, 172, 96, 60, 227, 233, 64, 255, 224, 173, 225, 228, 229, 92, 112, 72, 99, 97, 26, 87, 187, 123, 46, 50, 90, 202, 117, 73, 10, 153, 47, 224, 178, 163, 77, 48, 46, 154, 33, 148, 34, 228, 33, 172, 216, 89, 46, 225, 127, 68, 146, 234, 30, 147, 54, 146, 5, 133, 45, 78, 254, 85, 55, 75, 213, 86, 194, 218, 215, 163, 189, 194, 54, 6, 83, 36, 18, 153, 53, 7, 48, 89, 35, 66, 144, 7, 65, 154, 13, 97, 75, 55, 230, 132, 3, 13, 239, 71]) 
  #     @rsa.e = make_bn([1, 0, 1])
  #     @rsa.d = make_bn([84, 80, 150, 58, 165, 235, 242, 123, 217, 55, 38, 154, 36, 181, 221, 156, 211, 215, 100, 164, 90, 88, 40, 228, 83, 148, 54, 122, 4, 16, 165, 48, 76, 194, 26, 107, 51, 53, 179, 165, 31, 18, 198, 173, 78, 61, 56, 97, 252, 158, 140, 80, 63, 25, 223, 156, 36, 203, 214, 252, 120, 67, 180, 167, 3, 82, 243, 25, 97, 214, 83, 133, 69, 16, 104, 54, 160, 200, 41, 83, 164, 187, 70, 153, 111, 234, 242, 158, 175, 28, 198, 48, 211, 45, 148, 58, 23, 62, 227, 74, 52, 117, 42, 90, 41, 249, 130, 154, 80, 119, 61, 26, 193, 40, 125, 10, 152, 174, 227, 225, 205, 32, 62, 66, 6, 163, 100, 99, 219, 19, 253, 25, 105, 80, 201, 29, 252, 157, 237, 69, 1, 80, 171, 167, 20, 196, 156, 109, 249, 88, 0, 3, 152, 38, 165, 72, 87, 6, 152, 71, 156, 214, 16, 71, 30, 82, 51, 103, 76, 218, 63, 9, 84, 163, 249, 91, 215, 44, 238, 85, 101, 240, 148, 1, 82, 224, 91, 135, 105, 127, 84, 171, 181, 152, 210, 183, 126, 24, 46, 196, 90, 173, 38, 245, 219, 186, 222, 27, 240, 212, 194, 15, 66, 135, 226, 178, 190, 52, 245, 74, 65, 224, 81, 100, 85, 25, 204, 165, 203, 187, 175, 84, 100, 82, 15, 11, 23, 202, 151, 107, 54, 41, 207, 3, 136, 229, 134, 131, 93, 139, 50, 182, 204, 93, 130, 89])
  #   end

  #   it 'can decrypt the example token' do
  #     token = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0.ZmnlqWgjXyqwjr7cXHys8F79anIUI6J2UWdAyRQEcGBU-KPHsePM910_RoTDGu1IW40Dn0dvcdVEjpJcPPNIbzWcMxDi131Ejeg-b8ViW5YX5oRdYdiR4gMSDDB3mbkInMNUFT-PK5CuZRnHB2rUK5fhPuF6XFqLLZCG5Q_rJm6Evex-XLcNQAJNa1-6CIU12Wj3mPExxw9vbnsQDU7B4BfmhdyiflLA7Ae5ZGoVRl3A__yLPXxRjHFhpOeDp_adx8NyejF5cz9yDKULugNsDMdlHeJQOMGVLYaSZt3KP6aWNSqFA1PHDg-10ceuTEtq_vPE4-Gtev4N4K4Eudlj4Q.AxY8DCtDaGlsbGljb3RoZQ.Rxsjg6PIExcmGSF7LnSEkDqWIKfAw1wZz2XpabV5PwQsolKwEauWYZNE9Q1hZJEZ.8LXqMd0JLGsxMaB5uoNaMpg7uUW_p40RlaZHCwMIyzk'
  #     payload = Sandal.decode_token(token) do |header|
  #       alg = Sandal::Enc::Alg::RSA1_5.new(@rsa)
  #       Sandal::Enc::A128CBC_HS256.new(alg)
  #     end
  #     payload.should == 'No matter where you go, there you are.'
  #   end

  #   it 'raises a token error when the integrity value is changed' do
  #     token = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0.ZmnlqWgjXyqwjr7cXHys8F79anIUI6J2UWdAyRQEcGBU-KPHsePM910_RoTDGu1IW40Dn0dvcdVEjpJcPPNIbzWcMxDi131Ejeg-b8ViW5YX5oRdYdiR4gMSDDB3mbkInMNUFT-PK5CuZRnHB2rUK5fhPuF6XFqLLZCG5Q_rJm6Evex-XLcNQAJNa1-6CIU12Wj3mPExxw9vbnsQDU7B4BfmhdyiflLA7Ae5ZGoVRl3A__yLPXxRjHFhpOeDp_adx8NyejF5cz9yDKULugNsDMdlHeJQOMGVLYaSZt3KP6aWNSqFA1PHDg-10ceuTEtq_vPE4-Gtev4N4K4Eudlj4Q.AxY8DCtDaGlsbGljb3RoZQ.Rxsjg6PIExcmGSF7LnSEkDqWIKfAw1wZz2XpabV5PwQsolKwEauWYZNE9Q1hZJEZ.7V5ZDko0v_mf2PAc4JMiUg'
  #     expect { Sandal.decode_token(token) do |header|
  #       alg = Sandal::Enc::Alg::RSA1_5.new(@rsa)
  #       Sandal::Enc::A128CBC_HS256.new(alg)
  #     end }.to raise_error Sandal::TokenError, 'Invalid integrity value.'
  #   end

  # end

  # it 'raises a token error when the RSA keys JWE section A.2 are changed' do
  #   token = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0.ZmnlqWgjXyqwjr7cXHys8F79anIUI6J2UWdAyRQEcGBU-KPHsePM910_RoTDGu1IW40Dn0dvcdVEjpJcPPNIbzWcMxDi131Ejeg-b8ViW5YX5oRdYdiR4gMSDDB3mbkInMNUFT-PK5CuZRnHB2rUK5fhPuF6XFqLLZCG5Q_rJm6Evex-XLcNQAJNa1-6CIU12Wj3mPExxw9vbnsQDU7B4BfmhdyiflLA7Ae5ZGoVRl3A__yLPXxRjHFhpOeDp_adx8NyejF5cz9yDKULugNsDMdlHeJQOMGVLYaSZt3KP6aWNSqFA1PHDg-10ceuTEtq_vPE4-Gtev4N4K4Eudlj4Q.AxY8DCtDaGlsbGljb3RoZQ.Rxsjg6PIExcmGSF7LnSEkDqWIKfAw1wZz2XpabV5PwQsolKwEauWYZNE9Q1hZJEZ.8LXqMd0JLGsxMaB5uoNaMpg7uUW_p40RlaZHCwMIyzk'
  #   expect { Sandal.decode_token(token) do |header|
  #     rsa = OpenSSL::PKey::RSA.new(2048)
  #     alg = Sandal::Enc::Alg::RSA1_5.new(rsa)
  #     Sandal::Enc::A128CBC_HS256.new(alg)
  #   end }.to raise_error Sandal::TokenError, 'Cannot decrypt content master key.'
  # end

end

