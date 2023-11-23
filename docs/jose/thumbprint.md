The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the
X.509 certificate ([RFC 5280][RFC5280]) corresponding to the key used to digitally sign
the JWS. Note that certificate thumbprints are also sometimes known as
certificate fingerprints. Use of this Header Parameter is OPTIONAL.

[RFC5280]: https://tools.ietf.org/html/rfc5280
