module Sandal
  # Contains JSON encode and decode functionality.
  module Json
    if !defined?(MultiJson)
      require 'json'

      # Decode a JSON string into Ruby.  This version delegates to the included JSON engine.
      #
      # @param encoded [String] The JSON string representation of the object.
      # @return The decoded Ruby object.
      def self.load(encoded)
        JSON.parse(encoded)
      end

      # Encodes a Ruby object as JSON.  This version delegates to the included JSON engine.
      #
      # @param raw The Ruby object to be encoded
      # @return [String] The JSON string representation of the object.
      def self.dump(raw)
        JSON.generate(raw)
      end

    else
      require 'multi_json'

      # Decode a JSON string into Ruby.  This version delegates to MultiJson.
      #
      # @param encoded [String] The JSON string representation of the object.
      # @return The decoded Ruby object.
      def self.load(encoded)
        MultiJson.load(encoded)
      end

      # Encodes a Ruby object as JSON.  This version delegates to MultiJson.
      #
      # @param raw The Ruby object to be encoded
      # @return [String] The JSON string representation of the object.
      def self.dump(raw)
        MultiJson.dump(raw)
      end
    end
  end
end