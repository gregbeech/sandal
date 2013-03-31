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

  it 'raises a token error if base64 strings contain padding' do
    expect { Sandal::Util.base64_decode('eyJpc3MiOiJq=') }.to raise_error Sandal::TokenError
  end

  it 'compares nil strings as equal' do
    Sandal::Util.secure_equals(nil, nil).should == true
  end

  it 'compares nil strings as unequal to empty strings' do
    Sandal::Util.secure_equals(nil, '').should == false
    Sandal::Util.secure_equals('', nil).should == false
  end

  it 'compares equal strings as equal' do
    Sandal::Util.secure_equals('hello', 'hello').should == true
    Sandal::Util.secure_equals('a longer string', 'a longer string').should == true
  end

  it 'compares unequal strings as unequal' do
    Sandal::Util.secure_equals('hello', 'world').should == false
    Sandal::Util.secure_equals('a longer string', 'a different longer string').should == false
  end

end