require 'helper'
require 'openssl'
require 'benchmark'

include Sandal::Util

describe Sandal::Util do

  it 'encodes and decodes base64 as per JWT example 6.1' do
    src =  "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}" 
    encoded = jwt_base64_encode(src)
    encoded.should == 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    val = jwt_base64_decode(encoded)
    val.should == src
  end

  it 'raises an argument error if base64 strings contain padding' do
    expect { jwt_base64_decode('eyJpc3MiOiJq=') }.to raise_error ArgumentError
  end

  it 'raises an argument error if base64 strings are invalid' do
    expect { jwt_base64_decode('not valid base64') }.to raise_error ArgumentError
  end

  it 'compares nil strings as equal' do
    jwt_strings_equal?(nil, nil).should == true
  end

  it 'compares nil strings as unequal to empty strings' do
    jwt_strings_equal?(nil, '').should == false
    jwt_strings_equal?('', nil).should == false
  end

  it 'compares equal strings as equal' do
    jwt_strings_equal?('hello', 'hello').should == true
    jwt_strings_equal?('a longer string', 'a longer string').should == true
  end

  it 'compares unequal strings as unequal' do
    jwt_strings_equal?('hello', 'world').should == false
    jwt_strings_equal?('a longer string', 'a different longer string').should == false
  end

  it 'compares strings without short-circuiting', :timing_dependent do
    measure_equals = -> a, b do
      Benchmark.realtime { 100.times { jwt_strings_equal?(a, b) } } 
    end
    ref = 'a' * 10000
    cmp1 = ('a' * 9999) + 'b'
    cmp2 = 'a' + ('b' * 9999)
    t1 = measure_equals.(ref, cmp1)
    t2 = measure_equals.(ref, cmp2)
    range = (t1 - t1/20.0)..(t1 + t1/20.0)
    range.should === t2
  end

end