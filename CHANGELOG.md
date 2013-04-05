## 0.2.0

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