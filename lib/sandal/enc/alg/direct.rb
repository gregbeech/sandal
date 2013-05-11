require 'openssl'

module Sandal
  module Enc
    module Alg

      # The direct ("dir") key encryption mechanism, which uses a pre-shared 
      # content master key.
      class Direct

        # @return [String] The JWA name of the algorithm.
        attr_reader :name

        # @return [String] The pre-shared key.
        attr_reader :direct_key

        # Creates a new instance.
        #
        # @param cmk [String] The pre-shared key.
        def initialize(direct_key)
          @name = 'dir'
          @direct_key = direct_key
        end

        # Returns an empty string as the content master key is not included in 
        # the JWE token.
        #
        # @param cmk [String] This parameter is ignored.
        # @return [String] An empty string.
        def encrypt_cmk(cmk)
          ''
        end

        # Returns the pre-shared content master key.
        #
        # @param encrypted_cmk [String] The encrypted content master key.
        # @return [String] The pre-shared content master key.
        # @raise [Sandal::TokenError] encrypted_cmk is not nil or empty.
        def decrypt_cmk(encrypted_cmk)
          unless encrypted_cmk.nil? || encrypted_cmk.empty?
            raise Sandal::InvalidTokenError, 'Token must not include encrypted CMK.' 
          end
          @direct_key
        end

      end

    end
  end
end