require "helper"
require "openssl"
require_relative "shared_examples"

# TODO: These tests are really for the Sandal module rather than just the algorithm -- move them!

describe Sandal::Enc::A256CBC_HS512 do
  include_examples "algorithm compatibility", Sandal::Enc::A256CBC_HS512
  include_examples "invalid tokens", Sandal::Enc::A256CBC_HS512

  context "#name" do
    it "is 'A256CBC-HS512'" do
      enc = Sandal::Enc::A256CBC_HS512.new(Sandal::Enc::Alg::Direct.new("a cmk"))
      expect(enc.name).to eq("A256CBC-HS512")
    end
  end

end

