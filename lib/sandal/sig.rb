module Sandal
  # Common signature traits.
  module Sig

    # The JWA name of the algorithm.
    attr_reader :name

    # Signs data and returns the signature.
    def sign(data)
      throw NotImplementedError.new("#{@name}.sign is not implemented.")
    end

    # Verifies a signature and returns whether the signature matches.
    def verify(signature, data)
      throw NotImplementedError.new("#{@name}.verify is not implemented.")
    end

    # The 'none' JWA signature method.
    class None
      include Sandal::Sig

      # Creates a new instance.
      def initialize
        @name = 'none'
      end

      # Returns an empty signature.
      def sign(data)
        ''
      end

      # Verifies that the signature is empty.
      def verify(signature, data)
        signature.nil? || signature.length == 0
      end

    end

  end
end

require 'sandal/sig/rs'