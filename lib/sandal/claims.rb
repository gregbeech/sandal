module Sandal
  # A module that can be mixed into Hash-like objects to provide claims-related
  # functionality.
  module Claims

    # Validates the set of claims.
    #
    # @param options [Hash] The validation options (see 
    #   {Sandal::DEFAULT_OPTIONS} for details).
    # @return [Hash] A reference to self.
    # @raise [Sandal::ClaimError] One or more claims is invalid.
    def validate_claims(options)
      validate_exp(options[:max_clock_skew]) if options[:validate_exp]
      validate_nbf(options[:max_clock_skew]) if options[:validate_nbf]
      validate_iss(options[:valid_iss])
      validate_aud(options[:valid_aud])
      self
    end

    # Validates the expires claim.
    #
    # @param max_clock_skew [Numeric] The maximum clock skew, in seconds.
    # @return [void].
    # @raise [Sandal::ClaimError] The 'exp' claim is invalid, or the token has 
    #   expired.
    def validate_exp(max_clock_skew)
      exp = time_claim('exp')
      if exp && exp <= (Time.now - max_clock_skew)
        raise Sandal::ClaimError, 'The token has expired.' 
      end
      nil
    end

    # Validates the not-before claim.
    #
    # @param max_clock_skew [Numeric] The maximum clock skew, in seconds.
    # @return [void].
    # @raise [Sandal::ClaimError] The 'nbf' claim is invalid, or the token is 
    #   not valid yet.
    def validate_nbf(max_clock_skew)
      nbf = time_claim('nbf')
      if nbf && nbf > (Time.now + max_clock_skew)
        raise Sandal::ClaimError, 'The token is not valid yet.'
      end
    end

    # Validates the issuer claim.
    #
    # @param valid_iss [Array] The valid issuers.
    # @return [void].
    # @raise [Sandal::ClaimError] The 'iss' claim value is not a valid issuer.
    def validate_iss(valid_iss)
      if valid_iss && valid_iss.length > 0 && !valid_iss.include?(self['iss'])
        raise Sandal::ClaimError, 'The issuer is invalid.'
      end
    end

    # Validates the audience claim.
    #
    # @param valid_aud [Array] The valid audiences.
    # @return [void].
    # @raise [Sandal::ClaimError] The 'aud' claim value does not contain a valid
    # audience.
    def validate_aud(valid_aud)
      if valid_aud && valid_aud.length > 0
        aud = self['aud']
        aud = [aud] unless aud.is_a?(Array)
        unless (aud & valid_aud).length > 0
          raise Sandal::ClaimError, 'The audence is invalid.'
        end
      end
    end

    private

    # Gets the value of a claim as a Time.
    def time_claim(name)
      claim = self[name]
      if claim
        begin
          Time.at(claim)
        rescue
          raise ClaimError, "The '#{name}' claim is invalid."
        end
      end
    end

  end
end