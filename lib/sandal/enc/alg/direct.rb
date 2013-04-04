require 'openssl'

module Sandal
  module Enc
    module Alg

      class Direct

        attr_reader :name
        attr_reader :cmk

        def initialize(cmk)
          @name = 'dir'
          @cmk = cmk
        end

        def encrypt_cmk(cmk)
          ''
        end

        def decrypt_cmk(encrypted_cmk)
          @cmk
        end

      end

    end
  end
end