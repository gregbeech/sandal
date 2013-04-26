## 0.4.0

Features:

- The decode_token method now recursively decodes/decrypts nested tokens rather than requiring multiple calls.

Breaking changes:

- The decode_token method is now used for both signed and encrypted tokens; the decrypt_token method has been removed.

Bug fixes:

- The zip parameter is now used in JWE tokens.

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