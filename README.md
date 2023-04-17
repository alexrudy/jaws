# JAWS: JSON Web tokens

Extracted from [yacme](github.com/alexrudy/yacme) as a starting point.

Built on [RustCrypto](github.com/RustCrypto/)

No OpenSSL depedency.

Strongly typed tokens.

## Features

1. Strongly typed, wherever possible. The types in this crate should accurately
    model only the valid states for a JWT, and should make misuse of this JWT
    very difficult. If there are "foot guns" or places where the type system
    and API interface do not accurately represent the state of JWTs, I'd like
    to know and attempt to correct them.
2. Construct a JWT with a potentially custom payload and custom headers, but with
    strongly typed support for the registered claims and headers.
3. Broad support for cryptography algorithms supported in RustCrypto.
4. Easy API interface, which produces simple and ergonomic code.
