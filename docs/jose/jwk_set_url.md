The "jku" (JWK Set URL) Header Parameter is a URI ([RFC 3986][RFC3986]) that refers to a
resource for a set of JSON-encoded public keys, one of which corresponds to
the key used to digitally sign the JWS. The keys MUST be encoded as a JWK
Set ([JWK][]). The protocol used to acquire the resource MUST provide integrity
protection; an HTTP GET request to retrieve the JWK Set MUST use Transport
Layer Security (TLS) ([RFC 2818][RFC2818]) ([RFC 5246][RFC5246]); and the identity of the server
MUST be validated, as per Section 6 of [RFC 6125][RFC6125]. Also, see Section
8 on TLS requirements. Use of this Header Parameter is OPTIONAL.

[JWK]: https://tools.ietf.org/html/rfc7517
[RFC2818]: https://tools.ietf.org/html/rfc2818
[RFC3986]: https://tools.ietf.org/html/rfc3986
[RFC5246]: https://tools.ietf.org/html/rfc5246
[RFC6125]: https://tools.ietf.org/html/rfc6125
