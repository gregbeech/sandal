require 'helper'
require 'openssl'

describe Sandal::Sig::HS256 do
  it 'can sign data and verify signatures' do
    data = 'Hello HS256'
    key = 'A secret key'
    signer = Sandal::Sig::HS256.new(key)
    signature = signer.sign(data)
    signer.verify(signature, data).should == true
  end
end

describe Sandal::Sig::HS384 do
  it 'can sign data and verify signatures' do
    data = 'Hello HS384'
    key = 'Another secret key'
    signer = Sandal::Sig::HS384.new(key)
    signature = signer.sign(data)
    signer.verify(signature, data).should == true
  end
end

describe Sandal::Sig::HS512 do
  it 'can sign data and verify signatures' do
    data = 'Hello HS512'
    key = 'Yet another secret key'
    signer = Sandal::Sig::HS512.new(key)
    signature = signer.sign(data)
    signer.verify(signature, data).should == true
  end
end