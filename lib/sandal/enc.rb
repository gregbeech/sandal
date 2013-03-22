module Sandal
  # Common encryption traits.
  module Enc

    # The JWA name of the encryption.
    attr_reader :name

    # The JWA name of the algorithm.
    attr_reader :alg_name

    def encrypt(header, payload)
      throw NotImplementedError.new("#{@name}.encrypt is not implemented.")
    end

    def decrypt(data)
      throw NotImplementedError.new("#{@name}.decrypt is not implemented.")
    end

  end
end

require 'sandal/enc/aescbc'