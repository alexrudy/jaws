# Changelog

## Unreleased

## [3.0.0](https://github.com/alexrudy/jaws/compare/v2.1.2...v3.0.0) - 2026-11-22

### Added

- add support for claim validation
- Validate JWKSets when restricted.
- Validate tokens using a JWKS

### Other

- cargo clippy
- Fixup doctests
- Fix feature dependencies for tests/claims
- Move claims behind a feature
- jiff wrapper type for serde
- migrate from chrono to jiff
- Merge pull request #79 from alexrudy/chore/rust-2024
- Merge pull request #76 from alexrudy/bugfix/numeric-date
- clippy fix for rust 2024
- fmt change for 2024
- upgrade to rust 2024
- fixes
- Review follow-ups
- Header lifetimes come from token
- Expose the chrono serde implementation for JWTs

## [2.1.2](https://github.com/alexrudy/jaws/compare/v2.1.1...v2.1.2) - 2026-11-22

### Other

- Merge pull request #74 from alexrudy/bugfix/serde-bounds
- remove unnecessary serde bounds

## [2.1.1](https://github.com/alexrudy/jaws/compare/v2.1.0...v2.2.0) - 2026-11-21

### Fixed

- JWK Set skips unknown/invalid keys

## [2.1.0](https://github.com/alexrudy/jaws/compare/v2.0.1...v2.1.0) - 2026-11-21

- Support for JSON Web Key Sets (RFC 7517)
- PrivateJWKey and PublicJWKey types to represent JWKs
- SigningJWKey and VerifyingJWKey types to represent JWKs with signature algorithms
- Better types for algorithms, key types, and SHA algorithms
- Support for the `none` algorithm for JWS

### Bugfixes
- EC keys serialize `d` correctly
- PSS private keys correctly include private parameters
- HMAC Key serializes octets correctly
- JWK Error is now `#[non_exhaustive]`

## [2.0.1](https://github.com/alexrudy/jaws/compare/v2.0.0...v2.0.1) - 2026-11-10

### Other

- Bump RSA to released version 0.10

## [2.0.0](https://github.com/alexrudy/jaws/compare/v1.0.5...v2.0.0) - 2026-09-26

### Added

- *(token)* Unify the Verified and Signed types

## [1.0.5](https://github.com/alexrudy/jaws/compare/v1.0.4...v1.0.5) - 2026-09-25

## [1.0.4](https://github.com/alexrudy/jaws/compare/v1.0.3...v1.0.4) - 2026-06-05

## [1.0.3](https://github.com/alexrudy/jaws/compare/v1.0.2...v1.0.3) - 2026-01-25

## [1.0.2](https://github.com/alexrudy/jaws/compare/v1.0.1...v1.0.2) - 2025-12-10

## [1.0.1](https://github.com/alexrudy/jaws/releases/tag/1.0.1)

Every patch will bump dependencies as appropriate.

### Bugfixes and Improvements
- [PR#29](https://github.com/alexrudy/jaws/pull/29) Fixed misspelled feature configuration items.
