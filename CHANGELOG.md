## 0.1.1

Features:

- Changed from json to multi_json.
- Added a new Claims module which can be mixed in.

Bug fixes:

- Base64 decoding now ensures there is no padding before decoding.

## 0.1.0 (30 March 2013)

The first version worth using.

Features:

- Supports all JWA signature algorithms (ES, HS, RS, none).
- Validates exp, nbf, iss and aud claims.
- Configurable token validation options.