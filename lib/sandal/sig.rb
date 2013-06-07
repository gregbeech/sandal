require "singleton"

module Sandal
  # Contains signature (JWS) functionality.
  module Sig

    # The "none" JWA signature method.
    class None
      include Singleton

      # The JWA name of the algorithm.
      NAME = "none"

      # The JWA name of the algorithm.
      def name
        NAME
      end

      # Returns an empty signature.
      #
      # @param payload [String] This parameter is ignored.
      # @return [String] An empty string.
      def sign(payload)
        ""
      end

      # Validates that a signature is nil or empty.
      #
      # @param signature [String] The signature to validate.
      # @param payload [String] This parameter is ignored.
      # @return [Boolean] true if the signature is nil/empty; otherwise false.
      def valid?(signature, payload)
        signature.nil? || signature.empty?
      end

    end

    # The singleton instance of the Sandal::Sig::None signature method.
    NONE = Sandal::Sig::None.instance

  end
end

require "sandal/sig/es" unless RUBY_PLATFORM == "java"
require "sandal/sig/hs"
require "sandal/sig/rs"