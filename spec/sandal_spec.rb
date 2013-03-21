require 'helper'

describe Sandal do

  it 'encodes and decodes JWTs with no signature' do
    header = {}
    payload = 'Hello, World'
    token = Sandal.encode_token({}, payload)
    decoded_payload = Sandal.decode_token(token)
    decoded_payload.should == payload
  end

end