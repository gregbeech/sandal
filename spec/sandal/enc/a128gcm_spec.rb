require "helper"
require "openssl"
require_relative "shared_examples"

if defined? Sandal::Enc::A128GCM

describe Sandal::Enc::A128GCM do
  include_examples "algorithm compatibility", Sandal::Enc::A128GCM
  include_examples "invalid tokens", Sandal::Enc::A128GCM

  context "#name" do
    it "is 'A128GCM'" do
      enc = Sandal::Enc::A128GCM.new(Sandal::Enc::Alg::Direct.new("a cmk"))
      enc.name.should == "A128GCM"
    end
  end

end

end