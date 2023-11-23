The "x5c" (X.509 certificate chain) Header Parameter contains the X.509 public
key certificate or certificate chain ([RFC 5280][RFC5280]) corresponding to the key used
to digitally sign the JWS. The certificate or certificate chain is represented
as a JSON array of certificate value strings. Each string in the array is a
base64-encoded (Section 4 of [RFC 4648][RFC4648] -- not base64url-encoded) DER
([ITU.X690.2008][]) PKIX certificate value. The certificate containing the public
key corresponding to the key used to digitally sign the JWS MUST be the first
certificate. This MAY be followed by additional certificates, with each
subsequent certificate being the one used to certify the previous one. The
recipient MUST validate the certificate chain according to [RFC 5280][RFC5280]
and consider the certificate or certificate chain to be invalid if any
validation failure occurs. Use of this Header Parameter is OPTIONAL.

[RFC4648]: https://tools.ietf.org/html/rfc4648
[RFC5280]: https://tools.ietf.org/html/rfc5280
[ITU.X690.2008]: hhttps://www.itu.int/rec/T-REC-X.680-X.693-200811-S/en
