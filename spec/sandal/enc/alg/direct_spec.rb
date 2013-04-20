require 'helper'
require 'openssl'

describe Sandal::Enc::Alg::Direct do

  context '#name' do

    it 'is "dir"' do
      alg = Sandal::Enc::Alg::Direct.new('some cmk')
      alg.name.should == 'dir'
    end

  end

  context '#cmk' do

    it 'returns the real CMK' do
      cmk = 'the real cmk'
      alg = Sandal::Enc::Alg::Direct.new(cmk)
      alg.cmk.should == cmk
    end

  end

  context '#encrypt_cmk' do

    it 'returns an empty string' do
      alg = Sandal::Enc::Alg::Direct.new('the real cmk')
      alg.encrypt_cmk('any value').should == ''
    end

  end

  context '#decrypt_cmk' do

    it 'returns the real CMK when the value to decrypt is nil' do
      cmk = 'the real cmk'
      alg = Sandal::Enc::Alg::Direct.new(cmk)
      alg.decrypt_cmk(nil).should == cmk
    end

    it 'returns the real CMK when the value to decrypt is empty' do
      cmk = 'the real cmk'
      alg = Sandal::Enc::Alg::Direct.new(cmk)
      alg.decrypt_cmk('').should == cmk
    end

    it 'raises a TokenError if the value to decrypt is not nil or empty' do
      alg = Sandal::Enc::Alg::Direct.new('the real cmk')
      expect { alg.decrypt_cmk('a value') }.to raise_error Sandal::TokenError
    end

  end

end