require "helper"
require "openssl"
require_relative "shared_examples"

describe Sandal::Enc::A128CBC_HS256 do
  include_examples "algorithm compatibility", Sandal::Enc::A128CBC_HS256
  include_examples "invalid tokens", Sandal::Enc::A128CBC_HS256

  context "#name" do
    it "is 'A128CBC-HS256'" do
      enc = Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::Direct.new("a cmk"))
      enc.name.should == "A128CBC-HS256"
    end
  end

  context "#decrypt" do
    it "can decrypt the example token from JWE draft-11 appendix 2", :jruby_incompatible do
      token="eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw"
      enc = Sandal::Enc::A128CBC_HS256.new(Sandal::Enc::Alg::RSA1_5.new(SampleKeys.jwe_draft11_appendix2_rsa))
      enc.decrypt(token).should == "Live long and prosper."
    end
  end

end

