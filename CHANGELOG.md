# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## [1.0.1]
### Fixed
- `wrap-authenticate` now accepts the same values for `public-key` as `authentic?`

## [1.0.0]
### Added
- Unit tests
- GitHub test action
- `ring-discord-auth.core/verify` as a replacement for plain signature validation in `authentic?`
- `ring-discord-auth.core/new-verifier` and `public-key->signer-verifier` for convenience with the new library
- `authentic?` accepts an `Ed25519Signer` as public key

### Changed
- `wrap-authenticate` is now in `ring-discord-auth.ring`
- Use of bouncycastle library instead of caesium (native libsodium is not required anymore)

### Removed
- Simple `authentic?` arity (replaced by `verify` function)

## 0.2.1
### Changed
- New Licence: MIT

## 0.2.0
### Added 
- Support for async ring handlers in `wrap-authenticate` middleware

## 0.1.0
### Added
- Initial project state

[1.0.0]: https://github.com/JohnnyJayJay/ring-discord-auth/tree/1.0.0
[1.0.1]: https://github.com/JohnnyJayJay/ring-discord-auth/tree/1.0.1
[Unreleased]: https://github.com/JohnnyJayJay/ring-discord-auth/tree/develop
