require 'helper'
require 'benchmark'

describe Sandal::Util do

  context '#strings_equal?' do

    it 'compares nil strings as equal' do
      expect(Sandal::Util.strings_equal?(nil, nil)).to eq(true)
    end

    it 'compares empty strings as equal' do
      expect(Sandal::Util.strings_equal?('', '')).to eq(true)
    end

    it 'compares nil strings as unequal to empty strings' do
      expect(Sandal::Util.strings_equal?(nil, '')).to eq(false)
      expect(Sandal::Util.strings_equal?('', nil)).to eq(false)
    end

    it 'compares equal strings as equal' do
      expect(Sandal::Util.strings_equal?('hello', 'hello')).to eq(true)
      expect(Sandal::Util.strings_equal?('a longer string', 'a longer string')).to eq(true)
    end

    it 'compares unequal strings as unequal' do
      expect(Sandal::Util.strings_equal?('hello', 'world')).to eq(false)
      expect(Sandal::Util.strings_equal?('a longer string', 'a different longer string')).to eq(false)
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
      expect(range).to be === t2
    end

  end

end