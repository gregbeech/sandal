module Sandal
  class JWK

    class EC < JWK

      KEY_TYPE = "EC"

      # The JWA name of the EC curve.
      attr_accessor :crv

      # The 'x' coordinate of the public key point.
      attr_accessor :x

      # The 'y' coordinate of the public key point.
      attr_accessor :y

      # The private key.
      attr_accessor :d

      def kty
        KEY_TYPE
      end

      def key
        group = make_group(crv)
        key = OpenSSL::PKey::EC.new(group)
        key.public_key = make_point(group, make_bn(x), make_bn(y))
        key.private_key = make_bn(d) if d
        key
      end

      def key=(key)
        self.crv = get_curve_name(key.group.curve_name)
        # TODO: Set other params!
      end

      def to_h
        h = super
        h.merge!({
          "crv" => crv
        })
      end

      private

      def make_group(curve_name)
        group_name = get_group_name(curve_name)
        OpenSSL::PKey::EC::Group.new(group_name) 
      end

      def make_point(group, x, y)
        group_size = group.curve_name.match(/(\d+)/)[0].to_i
        bn_size = ((group_size + 7) / 8) * 2
        str = "04" + x.to_s(16).rjust(bn_size, "0") + y.to_s(16).rjust(bn_size, "0")
        bn = OpenSSL::BN.new(str, 16)
        OpenSSL::PKey::EC::Point.new(group, bn)
      end

      def make_bn(str)
        hex_str = Sandal::Util.base64_decode(str).unpack('H*')[0]
        OpenSSL::BN.new(hex_str, 16)
      end

      def get_group_name(curve_name)
        case curve_name
        when "P-256" then "prime256v1"
        when "P-384" then "secp384r1"
        when "P-521" then "secp521r1"
        end
      end

      def get_curve_name(group_name)
        case group_name
        when "prime256v1" then "P-256" 
        when "secp384r1" then "P-384"
        when "secp521r1" then "P-521"
        end
      end

    end

  end
end