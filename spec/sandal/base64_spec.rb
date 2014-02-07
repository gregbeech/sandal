require 'helper'

describe Sandal::Base64 do

  context '#decode' do

    it 'decodes base64 as per JWT example 6.1' do
      encoded = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
      val = Sandal::Base64.decode(encoded)
      expect(val).to eq(%!{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}!)
    end

    it 'decodes arrays of base64 as per JWT example 6.1' do
      encoded = ['eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ']
      val = Sandal::Base64.decode(encoded)
      expect(val).to eq([%!{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}!])
    end

    it 'raises an ArgumentError if base64 strings contain padding' do
      expect { Sandal::Base64.decode('eyJpc3MiOiJq=') }.to raise_error ArgumentError
    end

    it 'raises an ArgumentError if base64 strings are invalid' do
      expect { Sandal::Base64.decode('not valid base64') }.to raise_error ArgumentError
    end

  end

  context '#encode' do

    it 'encodes base64 as per JWT example 6.1' do
      src =  %!{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}!
      encoded = Sandal::Base64.encode(src)
      expect(encoded).to eq('eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')
    end

    it 'encodes arrays of base64 as per JWT example 6.1' do
      src =  [%!{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}!]
      encoded = Sandal::Base64.encode(src)
      expect(encoded).to eq(['eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'])
    end

  end

end