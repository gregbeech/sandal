require 'openssl'

module Sandal
  # Contains encryption (JWE) functionality.
  module Enc

    # The Concat Key Derivation Function.
    #
    # @param digest [OpenSSL::Digest or String] The digest for the algorithm.
    # @param key [String] The key or shared secret.
    # @param keydatalen [Integer] The desired output size in bits.
    # @param algorithm_id [String] The name of the algorithm.
    # @param party_u_info [String or 0] The partyUInfo.
    # @param party_v_info [String or 0] The partyVInfo.
    # @param supp_pub_info [String] Supplementary public info.
    # @param supp_priv_info [String] Supplementary private info.
    # @return [String] The derived keying material.
    def self.concat_kdf(digest, key, keydatalen, algorithm_id, 
                        party_u_info, party_v_info, 
                        supp_pub_info = nil, supp_priv_info = nil)
      digest = OpenSSL::Digest.new(digest) if digest.is_a?(String)
      rounds = (keydatalen / (digest.digest_length * 8.0)).ceil

      round_input = concat_kdf_round_input(key, keydatalen, algorithm_id,
                                           party_u_info, party_v_info,
                                           supp_pub_info, supp_priv_info)

      (1..rounds).reduce('') do |output, round|
        hash = digest.digest([round].pack('N') + round_input)
        if round == rounds
          round_bits = keydatalen % (digest.digest_length * 8)
          hash = hash[0...(round_bits / 8)] unless round_bits == 0
        end
        output << hash
      end
    end

    private

    # The round input for the Concat KDF function (excluding round number).
    def self.concat_kdf_round_input(key, keydatalen, algorithm_id, 
                                    party_u_info, party_v_info, 
                                    supp_pub_info, supp_priv_info)
      input = ''
      input << key
      input << [keydatalen].pack('N')
      input << algorithm_id
      input << (party_u_info == 0 ? [0].pack('N') : party_u_info)
      input << (party_v_info == 0 ? [0].pack('N') : party_v_info)
      input << supp_pub_info if supp_pub_info
      input << supp_priv_info if supp_priv_info
      input
    end

  end
end

require 'sandal/enc/acbc_hs'
require 'sandal/enc/agcm' unless RUBY_VERSION < '2.0.0'
require 'sandal/enc/alg'