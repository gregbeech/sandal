require 'singleton'

module Sandal
  # Common signature traits.
  module Sig

    # @return [String] The JWA name of the algorithm.
    attr_reader :name

    # Signs a payload and returns the signature.
    #
    # @param payload [String] The payload of the token to sign.
    # @return [String] The signature.
    def sign(payload)
      raise NotImplementedError, "#{@name}.sign is not implemented."
    end

    # Validates a payload signature and returns whether the signature matches.
    #
    # @param signature [String] The signature to verify.
    # @param payload [String] The payload of the token.
    # @return [Boolean] true if the signature is correct; otherwise false.
    def valid?(signature, payload)
      raise NotImplementedError, "#{@name}.verify is not implemented."
    end

    # The 'none' JWA signature method.
    class None
      include Sandal::Sig
      include Singleton

      # Creates a new instance.
      def initialize
        @name = 'none'
      end

      # Returns an empty signature.
      #
      # @param payload [String] This parameter is ignored.
      # @return [String] An empty string.
      def sign(payload)
        ''
      end

      # Validates that a signature is nil or empty.
      #
      # @param signature [String] The signature to verify.
      # @param payload [String] This parameter is ignored.
      # @return [Boolean] `true` if the signature is nil or empty; otherwise `false`.
      def valid?(signature, payload)
        signature.nil? || signature.length == 0
      end

    end

  end
end

require 'sandal/sig/es'
require 'sandal/sig/hs'
require 'sandal/sig/rs'