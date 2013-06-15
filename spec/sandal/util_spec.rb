require 'helper'
require 'openssl'
require 'benchmark'

describe Sandal::Util do

  context '#base64_decode' do

    it 'decodes base64 as per JWT example 6.1' do
      encoded = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
      val = Sandal::Util.base64_decode(encoded)
      val.should == %!{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}!
    end

    it 'raises an ArgumentError if base64 strings contain padding' do
      expect { Sandal::Util.base64_decode('eyJpc3MiOiJq=') }.to raise_error ArgumentError
    end

    it 'raises an ArgumentError if base64 strings are invalid' do
      expect { Sandal::Util.base64_decode('not valid base64') }.to raise_error ArgumentError
    end

  end

  context '#base64_encode' do

    it 'encodes base64 as per JWT example 6.1' do
      src =  %!{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}!
      encoded = Sandal::Util.base64_encode(src)
      encoded.should == 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    end

  end

  context '#strings_equal?' do

    it 'compares nil strings as equal' do
      Sandal::Util.strings_equal?(nil, nil).should == true
    end

    it 'compares empty strings as equal' do
      Sandal::Util.strings_equal?('', '').should == true
    end

    it 'compares nil strings as unequal to empty strings' do
      Sandal::Util.strings_equal?(nil, '').should == false
      Sandal::Util.strings_equal?('', nil).should == false
    end

    it 'compares equal strings as equal' do
      Sandal::Util.strings_equal?('hello', 'hello').should == true
      Sandal::Util.strings_equal?('a longer string', 'a longer string').should == true
    end

    it 'compares unequal strings as unequal' do
      Sandal::Util.strings_equal?('hello', 'world').should == false
      Sandal::Util.strings_equal?('a longer string', 'a different longer string').should == false
    end

    it 'compares strings without short-circuiting', :timing_dependent do
      measure_equals = -> a, b do
        Benchmark.realtime { 100.times { Sandal::Util.strings_equal?(a, b) } } 
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

end