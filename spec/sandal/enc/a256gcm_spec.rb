require 'helper'
require 'openssl'
require 'securerandom'

# TODO: These tests are really for the Sandal module rather than just the algorithm -- move them!

if defined? Sandal::Enc::A256GCM

describe Sandal::Enc::A256GCM do

  # these tests don't run with jruby as it errors when you try and set rsa.d parameter directly
  context 'using the example RSA key from JWE section A.1', :jruby_incompatible do

    before :all do
      @rsa = OpenSSL::PKey::RSA.new(2048)
      @rsa.n = make_bn([161, 168, 84, 34, 133, 176, 208, 173, 46, 176, 163, 110, 57, 30, 135, 227, 9, 31, 226, 128, 84, 92, 116, 241, 70, 248, 27, 227, 193, 62, 5, 91, 241, 145, 224, 205, 141, 176, 184, 133, 239, 43, 81, 103, 9, 161, 153, 157, 179, 104, 123, 51, 189, 34, 152, 69, 97, 69, 78, 93, 140, 131, 87, 182, 169, 101, 92, 142, 3, 22, 167, 8, 212, 56, 35, 79, 210, 222, 192, 208, 252, 49, 109, 138, 173, 253, 210, 166, 201, 63, 102, 74, 5, 158, 41, 90, 144, 108, 160, 79, 10, 89, 222, 231, 172, 31, 227, 197, 0, 19, 72, 81, 138, 78, 136, 221, 121, 118, 196, 17, 146, 10, 244, 188, 72, 113, 55, 221, 162, 217, 171, 27, 57, 233, 210, 101, 236, 154, 199, 56, 138, 239, 101, 48, 198, 186, 202, 160, 76, 111, 234, 71, 57, 183, 5, 211, 171, 136, 126, 64, 40, 75, 58, 89, 244, 254, 107, 84, 103, 7, 236, 69, 163, 18, 180, 251, 58, 153, 46, 151, 174, 12, 103, 197, 181, 161, 162, 55, 250, 235, 123, 110, 17, 11, 158, 24, 47, 133, 8, 199, 235, 107, 126, 130, 246, 73, 195, 20, 108, 202, 176, 214, 187, 45, 146, 182, 118, 54, 32, 200, 61, 201, 71, 243, 1, 255, 131, 84, 37, 111, 211, 168, 228, 45, 192, 118, 27, 197, 235, 232, 36, 10, 230, 248, 190, 82, 182, 140, 35, 204, 108, 190, 253, 186, 186, 27])
      @rsa.e = make_bn([1, 0, 1])
      @rsa.d = make_bn([144, 183, 109, 34, 62, 134, 108, 57, 44, 252, 10, 66, 73, 54, 16, 181, 233, 92, 54, 219, 101, 42, 35, 178, 63, 51, 43, 92, 119, 136, 251, 41, 53, 23, 191, 164, 164, 60, 88, 227, 229, 152, 228, 213, 149, 228, 169, 237, 104, 71, 151, 75, 88, 252, 216, 77, 251, 231, 28, 97, 88, 193, 215, 202, 248, 216, 121, 195, 211, 245, 250, 112, 71, 243, 61, 129, 95, 39, 244, 122, 225, 217, 169, 211, 165, 48, 253, 220, 59, 122, 219, 42, 86, 223, 32, 236, 39, 48, 103, 78, 122, 216, 187, 88, 176, 89, 24, 1, 42, 177, 24, 99, 142, 170, 1, 146, 43, 3, 108, 64, 194, 121, 182, 95, 187, 134, 71, 88, 96, 134, 74, 131, 167, 69, 106, 143, 121, 27, 72, 44, 245, 95, 39, 194, 179, 175, 203, 122, 16, 112, 183, 17, 200, 202, 31, 17, 138, 156, 184, 210, 157, 184, 154, 131, 128, 110, 12, 85, 195, 122, 241, 79, 251, 229, 183, 117, 21, 123, 133, 142, 220, 153, 9, 59, 57, 105, 81, 255, 138, 77, 82, 54, 62, 216, 38, 249, 208, 17, 197, 49, 45, 19, 232, 157, 251, 131, 137, 175, 72, 126, 43, 229, 69, 179, 117, 82, 157, 213, 83, 35, 57, 210, 197, 252, 171, 143, 194, 11, 47, 163, 6, 253, 75, 252, 96, 11, 187, 84, 130, 210, 7, 121, 78, 91, 79, 57, 251, 138, 132, 220, 60, 224, 173, 56, 224, 201])
    end

    it 'can decrypt the example token' do
      token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.M2XxpbORKezKSzzQL_95-GjiudRBTqn_omS8z9xgoRb7L0Jw5UsEbxmtyHn2T71mrZLkjg4Mp8gbhYoltPkEOHvAopz25-vZ8C2e1cOaAo5WPcbSIuFcB4DjBOM3t0UAO6JHkWLuAEYoe58lcxIQneyKdaYSLbV9cKqoUoFQpvKWYRHZbfszIyfsa18rmgTjzrtLDTPnc09DSJE24aQ8w3i8RXEDthW9T1J6LsTH_vwHdwUgkI-tC2PNeGrnM-dNSfzF3Y7-lwcGy0FsdXkPXytvDV7y4pZeeUiQ-0VdibIN2AjjfW60nfrPuOjepMFG6BBBbR37pHcyzext9epOAQ.48V1_ALb6US04U3b._e21tGGhac_peEFkLXr2dMPUZiUkrw.7V5ZDko0v_mf2PAc4JMiUg'
      payload = Sandal.decrypt_token(token) do |header|
        alg = Sandal::Enc::Alg::RSA_OAEP.new(@rsa)
        Sandal::Enc::A256GCM.new(alg)
      end
      payload.should == 'Live long and prosper.'
    end

    it 'raises a token error when the integrity value is changed' do
      token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.M2XxpbORKezKSzzQL_95-GjiudRBTqn_omS8z9xgoRb7L0Jw5UsEbxmtyHn2T71mrZLkjg4Mp8gbhYoltPkEOHvAopz25-vZ8C2e1cOaAo5WPcbSIuFcB4DjBOM3t0UAO6JHkWLuAEYoe58lcxIQneyKdaYSLbV9cKqoUoFQpvKWYRHZbfszIyfsa18rmgTjzrtLDTPnc09DSJE24aQ8w3i8RXEDthW9T1J6LsTH_vwHdwUgkI-tC2PNeGrnM-dNSfzF3Y7-lwcGy0FsdXkPXytvDV7y4pZeeUiQ-0VdibIN2AjjfW60nfrPuOjepMFG6BBBbR37pHcyzext9epOAQ.48V1_ALb6US04U3b._e21tGGhac_peEFkLXr2dMPUZiUkrw.8LXqMd0JLGsxMaB5uoNaMpg7uUW_p40RlaZHCwMIyzk'
      expect { Sandal.decrypt_token(token) do |header|
        alg = Sandal::Enc::Alg::RSA_OAEP.new(@rsa)
        Sandal::Enc::A256GCM.new(alg)
      end }.to raise_error Sandal::TokenError, 'Invalid token.'
    end

  end

  it 'raises a token error when the RSA keys JWE section A.1 are changed' do
    token = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.M2XxpbORKezKSzzQL_95-GjiudRBTqn_omS8z9xgoRb7L0Jw5UsEbxmtyHn2T71mrZLkjg4Mp8gbhYoltPkEOHvAopz25-vZ8C2e1cOaAo5WPcbSIuFcB4DjBOM3t0UAO6JHkWLuAEYoe58lcxIQneyKdaYSLbV9cKqoUoFQpvKWYRHZbfszIyfsa18rmgTjzrtLDTPnc09DSJE24aQ8w3i8RXEDthW9T1J6LsTH_vwHdwUgkI-tC2PNeGrnM-dNSfzF3Y7-lwcGy0FsdXkPXytvDV7y4pZeeUiQ-0VdibIN2AjjfW60nfrPuOjepMFG6BBBbR37pHcyzext9epOAQ.48V1_ALb6US04U3b._e21tGGhac_peEFkLXr2dMPUZiUkrw.8LXqMd0JLGsxMaB5uoNaMpg7uUW_p40RlaZHCwMIyzk'
    expect { Sandal.decrypt_token(token) do |header|
      rsa = OpenSSL::PKey::RSA.new(2048)
      alg = Sandal::Enc::Alg::RSA_OAEP.new(rsa)
      Sandal::Enc::A256GCM.new(alg)
    end }.to raise_error Sandal::TokenError, 'Cannot decrypt content master key.'
  end

  it 'can encrypt and decrypt tokens with the RSA1_5 algorithm' do
    payload = 'Some other text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)

    encrypter = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA1_5.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)

    output = Sandal.decrypt_token(token) do 
      Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA1_5.new(rsa))
    end
    output.should == payload
  end

  it 'can encrypt and decrypt tokens with the RSA-OAEP algorithm' do
    payload = 'Some more text to encrypt'
    rsa = OpenSSL::PKey::RSA.new(2048)

    encrypter = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa.public_key))
    token = Sandal.encrypt_token(payload, encrypter)

    output = Sandal.decrypt_token(token) do 
      Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(rsa))
    end
    output.should == payload
  end

end

end