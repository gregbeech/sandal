module Sandal
  module Sig

    attr_reader :name

    def sign(data)
      throw NotImplementedError.new("#{@name}.sign is not implemented.")
    end

    def verify(signature, data)
      throw NotImplementedError.new("#{@name}.verify is not implemented.")
    end

    class None
      include Sandal::Sig

      def name
        'none'
      end

      def sign(data)
        ''
      end

      def verify(signature, data)
        signature.nil? || signature == ''
      end

    end

  end
end

require 'sandal/sig/rs'