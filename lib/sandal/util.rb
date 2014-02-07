require "base64"

module Sandal
  # @private
  # Implements some JWT utility functions. Shouldn't be needed by most people 
  # but may be useful if you're developing an extension to the library.
  module Util
    
    # A string equality function that compares Unicode codepoints, and also 
    # doesn't short-circuit the equality check to help protect against timing 
    # attacks.
    #--
    # http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/ 
    # for more info about timing attacks.
    #++
    #
    # @param a [String] The first string.
    # @param b [String] The second string.
    # @return [Boolean] true if the strings are equal; otherwise false.
    def self.strings_equal?(a, b)
      return true if a.object_id == b.object_id
      return false if a.nil? || b.nil? || a.length != b.length
      a.codepoints.zip(b.codepoints).reduce(0) { |r, (x, y)| r |= x ^ y } == 0
    end

  end
end