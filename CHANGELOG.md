## 0.5.0 (07 June 2013)

Features:

- Updated to JWT draft-08 specification, and corresponding JWE, JWS and JWA drafts.
- Added a KeyError class for when invalid keys are given to the library.
- Added an ExpiredTokenError class to make handling the common case of expired tokens easier.
- Added a NAME constant to all classes with a JWA name to save user having to hard-code the name string.

Breaking changes:

- Tokens are not backwards compatible with previous versions of the library due to changes in the specification.
- Dropped support for Ruby 1.9.2; supported platforms are now 1.9.3, 2.0.0, JRuby (head) and Rubinius (head).

## 0.4.0 (30 April 2013)

Features:

- The decode_token method now recursively decodes/decrypts nested tokens rather than requiring multiple calls.

Breaking changes:

- The decode_token method is now used for both signed and encrypted tokens; the decrypt_token method has been removed.

Bug fixes:

- The 'none' algorithm value is now always set in plaintext tokens.
- The zip parameter is now used when encrypting/decrypting JWE tokens.
- The Concat KDF function now works correctly when inputs have different string encodings by treating them all as binary.
- Errors related to jwt_base64_encode not being found when running under rack (although they worked fine under rspec) are resolved.

## 0.3.0 (20 April 2013)

Features:

- Keys can now be passed as strings as well as OpenSSL types.

Breaking changes:

- Default options have changed so that the behaviour is consistent with no options being passed.

Bug fixes:

- Strings are now compared by codepoint rather than by byte, in accordance with JWS § 5.3.
- Integrity value check in AES/CBC+HS algorithms now uses the constant time string comparison function rather than ==.
- Base64 decoding now checks that the decode was not lossy, as jruby would do a 'best effort' decode of invalid base64 strings.

## 0.2.0 (05 April 2013)

Features:

- Added support for AES/CBC and AES/GCM encryption methods.
- Added RSA1_5, RSA-OAEP and direct key protection algorithms.

Bug fixes:

- Sandal::Sig::ES class is now not included in jruby as ECDSA isn't supported.

## 0.1.1 (01 April 2013)

Features:

- Changed from json to multi_json gem for improved compatibility.
- New Claims module can add claims validation functionality to Hash-like objects.
- New ClaimError type for claim validation errors.

Bug fixes:

- Base64 decoding now ensures there is no padding before decoding.

## 0.1.0 (30 March 2013)

The first version worth using.

Features:

- Supports all JWA signature algorithms (ES, HS, RS, none).
- Validates exp, nbf, iss and aud claims.
- Configurable token validation options.