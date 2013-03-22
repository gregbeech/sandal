require 'helper'
require 'openssl'

describe Sandal::Util do

  it 'encodes and decodes base64 as per JWT example 6.1' do
    src =  "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}" 
    encoded = Sandal::Util.base64_encode(src)
    encoded.should == 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    val = Sandal::Util.base64_decode(encoded)
    val.should == src
  end

  it 'compares strings using a time-insensitive method' do
    # TODO: Probably need to look at the benchmark module for this
  end

end