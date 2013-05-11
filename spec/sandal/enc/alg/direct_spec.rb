require 'helper'
require 'openssl'

describe Sandal::Enc::Alg::Direct do

  context '#name' do

    it 'is "dir"' do
      alg = Sandal::Enc::Alg::Direct.new('some key')
      alg.name.should == 'dir'
    end

  end

  context '#direct_key' do

    it 'returns the real key' do
      key = 'the real key'
      alg = Sandal::Enc::Alg::Direct.new(key)
      alg.direct_key.should == key
    end

  end

  context '#encrypt_key' do

    it 'returns an empty string' do
      alg = Sandal::Enc::Alg::Direct.new('the real key')
      alg.encrypt_key('any value').should == ''
    end

  end

  context '#decrypt_key' do

    it 'returns the real CMK when the value to decrypt is nil' do
      key = 'the real key'
      alg = Sandal::Enc::Alg::Direct.new(key)
      alg.decrypt_key(nil).should == key
    end

    it 'returns the real CMK when the value to decrypt is empty' do
      key = 'the real key'
      alg = Sandal::Enc::Alg::Direct.new(key)
      alg.decrypt_key('').should == key
    end

    it 'raises a TokenError if the value to decrypt is not nil or empty' do
      alg = Sandal::Enc::Alg::Direct.new('the real key')
      expect { alg.decrypt_key('a value') }.to raise_error Sandal::TokenError
    end

  end

end