require 'helper'

describe Sandal::Claims do

  context '#validate_claims' do

    it 'calls #validate_aud when valid audiences are provided' do
      claims = { 'aud' => 'example.org' }.extend(Sandal::Claims)
      valid_aud = %w(example.org)
      expect(claims).to receive(:validate_aud).with(valid_aud)
      claims.validate_claims(valid_aud: valid_aud)
    end

    it 'calls #validate_exp by default' do
      claims = {}.extend(Sandal::Claims)
      expect(claims).to receive(:validate_exp)
      claims.validate_claims
    end

    it 'does not call #validate_exp when the :ignore_exp option is set' do
      claims = {}.extend(Sandal::Claims)
      expect(claims).not_to receive(:validate_exp)
      claims.validate_claims(ignore_exp: true)
    end

    it 'calls #validate_iss when valid issuers are provided' do
      claims = { 'iss' => 'example.org' }.extend(Sandal::Claims)
      valid_iss = %w(example.org)
      expect(claims).to receive(:validate_iss).with(valid_iss)
      claims.validate_claims(valid_iss: valid_iss)
    end

    it 'calls #validate_nbf by default' do
      claims = {}.extend(Sandal::Claims)
      expect(claims).to receive(:validate_nbf)
      claims.validate_claims
    end

    it 'does not call #validate_nbf when the :ignore_nbf option is set' do
      claims = {}.extend(Sandal::Claims)
      expect(claims).not_to receive(:validate_nbf)
      claims.validate_claims(ignore_nbf: true)
    end

  end

  context '#validate_aud' do

    it 'succeeds when the audience claim is missing and no valid audiences are given' do
      claims = {}.extend(Sandal::Claims)
      claims.validate_aud([])
    end

    it 'succeeds when the audience string is empty and no valid audiences are given' do
      claims = { 'aud' => '' }.extend(Sandal::Claims)
      claims.validate_aud([])
    end

    it 'succeeds when the audience string is the same as the valid audience' do
      claims = { 'aud' => 'example.org' }.extend(Sandal::Claims)
      claims.validate_aud(%w(example.org))
    end

    it 'succeeds when the audience string is the same as a valid audience' do
      claims = { 'aud' => 'example.org' }.extend(Sandal::Claims)
      claims.validate_aud(%w(example.org example.com))
    end

    it 'succeeds when the audience array is empty and no valid audiences are given' do
      claims = { 'aud' => [] }.extend(Sandal::Claims)
      claims.validate_aud([])
    end

    it 'succeeds when the audience array is the same as the valid audience' do
      claims = { 'aud' => %w(example.org) }.extend(Sandal::Claims)
      claims.validate_aud(%w(example.org))
    end

    it 'succeeds when the audience array contains a valid audience' do
      claims = { 'aud' => %w(example.org example.com) }.extend(Sandal::Claims)
      claims.validate_aud(%w(example.org))
    end

    it 'succeeds when the audience array contains multiple valid audiences' do
      claims = { 'aud' => %w(example.org example.com example.net) }.extend(Sandal::Claims)
      claims.validate_aud(%w(example.com example.org))
    end

    it 'raises a ClaimError when the audience claim is missing and a valid audience is given' do
      claims = {}.extend(Sandal::Claims)
      expect { claims.validate_aud(%w(example.org)) }.to raise_error Sandal::ClaimError
    end

    it 'raises a ClaimError when the audience string is empty and a valid audience is given' do
      claims = { 'aud' => '' }.extend(Sandal::Claims)
      expect { claims.validate_aud(%w(example.org)) }.to raise_error Sandal::ClaimError
    end

    it 'raises a ClaimError when the audience string does not contain a valid audience' do
      claims = { 'aud' => 'example.com' }.extend(Sandal::Claims)
      expect { claims.validate_aud(%w(example.org example.net)) }.to raise_error Sandal::ClaimError
    end

    it 'raises a ClaimError when the audience array is empty and a valid audience is given' do
      claims = { 'aud' => [] }.extend(Sandal::Claims)
      expect { claims.validate_aud(%w(example.org)) }.to raise_error Sandal::ClaimError
    end

    it 'raises a ClaimError when the audience array does not contain a valid audience' do
      claims = { 'aud' => %w(example.com example.net) }.extend(Sandal::Claims)
      expect { claims.validate_aud(%w(example.org)) }.to raise_error Sandal::ClaimError
    end

  end

  context '#validate_exp' do

    it 'succeeds when the expires claim is missing' do
      claims = {}.extend(Sandal::Claims)
      claims.validate_exp
    end

    it 'succeeds when the expiry time is in the future' do
      claims = { 'exp' => (Time.now + 300).to_i }.extend(Sandal::Claims)
      claims.validate_exp
    end

    it 'succeeds when the expiry time is in the past but within the max clock skew' do
      claims = { 'exp' => (Time.now - 60).to_i }.extend(Sandal::Claims)
      claims.validate_exp(120)
    end

    it 'raises an ExpiredTokenError when the expiry time is in the past with no clock skew' do
      claims = { 'exp' => (Time.now - 300).to_i }.extend(Sandal::Claims)
      expect { claims.validate_exp }.to raise_error Sandal::ExpiredTokenError
    end

    it 'raises an ExpiredTokenError when the expiry time is in the past and outside the max clock skew' do
      claims = { 'exp' => (Time.now - 300).to_i }.extend(Sandal::Claims)
      expect { claims.validate_exp(120) }.to raise_error Sandal::ExpiredTokenError
    end

  end

  context '#validate_iss' do

    it 'succeeds when the issuer claim is missing and no valid issuers are given' do
      claims = {}.extend(Sandal::Claims)
      claims.validate_iss([])
    end

    it 'succeeds when the issuer string is empty and no valid issuers are given' do
      claims = { 'iss' => '' }.extend(Sandal::Claims)
      claims.validate_iss([])
    end

    it 'succeeds when the issuer string is the same as the valid issuer' do
      claims = { 'iss' => 'example.org' }.extend(Sandal::Claims)
      claims.validate_iss(%w(example.org))
    end

    it 'succeeds when the issuer string is the same as a valid issuer' do
      claims = { 'iss' => 'example.org' }.extend(Sandal::Claims)
      claims.validate_iss(%w(example.org example.com))
    end

    it 'raises a ClaimError when the issuer claim is missing and a valid issuer is given' do
      claims = {}.extend(Sandal::Claims)
      expect { claims.validate_iss(%w(example.org)) }.to raise_error Sandal::ClaimError
    end

    it 'raises a ClaimError when the issuer string is empty and a valid issuer is given' do
      claims = { 'iss' => '' }.extend(Sandal::Claims)
      expect { claims.validate_iss(%w(example.org)) }.to raise_error Sandal::ClaimError
    end

    it 'raises a ClaimError when the issuer string is not a valid issuer' do
      claims = { 'iss' => 'example.com' }.extend(Sandal::Claims)
      expect { claims.validate_iss(%w(example.org example.net)) }.to raise_error Sandal::ClaimError
    end

  end

  context '#validate_nbf' do

    it 'succeeds when the not-before claim is missing' do
      claims = {}.extend(Sandal::Claims)
      claims.validate_nbf
    end

    it 'succeeds when the not-before time is in the past' do
      claims = { 'nbf' => (Time.now - 300).to_i }.extend(Sandal::Claims)
      claims.validate_nbf
    end

    it 'succeeds when the not-before time is in the future but within the max clock skew' do
      claims = { 'nbf' => (Time.now + 60).to_i }.extend(Sandal::Claims)
      claims.validate_nbf(120)
    end

    it 'raises a ClaimError when the not-before time is in the future with no clock skew' do
      claims = { 'nbf' => (Time.now + 300).to_i }.extend(Sandal::Claims)
      expect { claims.validate_nbf }.to raise_error Sandal::ClaimError
    end

    it 'raises a ClaimError when the not-before time is in the future and outside the max clock skew' do
      claims = { 'nbf' => (Time.now + 300).to_i }.extend(Sandal::Claims)
      expect { claims.validate_nbf(120) }.to raise_error Sandal::ClaimError
    end

  end

end