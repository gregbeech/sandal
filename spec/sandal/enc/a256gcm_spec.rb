require "helper"
require "openssl"
require_relative "shared_examples"

if defined? Sandal::Enc::A256GCM

describe Sandal::Enc::A256GCM do
  include_examples "algorithm compatibility", Sandal::Enc::A256GCM
  include_examples "invalid tokens", Sandal::Enc::A256GCM

  context "#name" do

    it "is 'A256GCM'" do
      enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::Direct.new("a cmk"))
      expect(enc.name).to eq("A256GCM")
    end

  end

  context "#decrypt" do
    it "can decrypt the example token from JWE draft-11 appendix 1", :jruby_incompatible do
      token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
      enc = Sandal::Enc::A256GCM.new(Sandal::Enc::Alg::RSA_OAEP.new(SampleKeys.jwe_draft11_appendix1_rsa))
      expect(enc.decrypt(token)).to eq("The true sign of intelligence is not knowledge but imagination.")
    end
  end

end

end