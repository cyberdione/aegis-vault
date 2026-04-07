# Changelog

All notable changes to aegis-vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**API not stable until 1.0.** Minor versions before 1.0 may break API.

## [Unreleased]

### Added
- Initial Rust crate `aegis-vault`:
  - Argon2id + HKDF + AES-256-GCM + HMAC-SHA256 primitives via RustCrypto
  - Ed25519 per-purpose key derivation via HKDF + domain-separated signing
  - Versioned meta and page blob formats with monotonic counters (sync-forward-compatible)
  - Wasm-bindgen API: `Vault::createNew`, `Vault::unlock`, `Vault::ephemeral`, `Vault::lock`
  - HSM-shaped `IdentityHandle` (no `seed()` accessor)
  - Page API: `pageGet`, `pageSet`, `pageDelete`, `pageEntries`, `pageEncrypt`, `pageLoad`
  - 33 native unit tests covering crypto round-trips, format encoding, identity derivation, page lifecycle, vault unlock, WebAuthn PRF, and purpose isolation
- Initial TS package `@cyberdione/aegis-vault-web`:
  - `AegisVault` wrapper with IDB persistence + locked/persistent state model
  - `loadVaultWasm()` lazy initialization
  - `BroadcastChannel('aegis-vault')` cross-tab coherence (notify-only in v0.1)
  - WebAuthn PRF helpers (`enrollWebAuthnPrf`, `assertWebAuthnPrf`)
- React subpackage `@cyberdione/aegis-vault-web/react`:
  - Headless `VaultProvider` + `useVault()` / `useVaultState()` hooks
  - Reference unstyled `VaultModal` component (consumers should build their own)
- README, THREATMODEL, LICENSE (Apache-2.0)

### Notes
- The term `anonymous` is deliberately absent from this codebase. See README §"Naming: avoiding `anonymous`" for the rationale.
- Phase B (Wanix worker isolation) is reserved behind the `wanix-worker` Cargo feature flag. Not implemented in v0.1.
