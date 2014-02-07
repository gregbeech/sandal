require "json"

module Sandal
  # Contains JSON encode and decode functionality.
  module Json

    # Decode a JSON string into Ruby.
    #
    # @param encoded [String] The JSON string representation of the object.
    # @return The decoded Ruby object.
    def self.load(encoded)
      JSON.parse(encoded)
    end

    # Encodes a Ruby object as JSON.
    #
    # @param raw The Ruby object to be encoded
    # @return [String] The JSON string representation of the object.
    def self.dump(raw)
      JSON.generate(raw)
    end
    
  end
end