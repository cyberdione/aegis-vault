# Changelog

All notable changes to aegis-vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**API not stable until 1.0.** Minor versions before 1.0 may break API.

## [0.3.0] — 2026-04-08

### Changed — repo layout (breaking for anyone pinned to the old paths)
- **Flattened the repo layout** so the npm package lives at the repo root instead of `packages/aegis-vault-web/`. This makes `"github:cyberdione/aegis-vault#v0.3.0"` git-URL installation work natively in npm — npm looks for `package.json` at the clone root and cannot descend into subdirectories without external tooling.
- `packages/aegis-vault-web/src/` → `src/`
- `packages/aegis-vault-web/package.json` → `package.json`
- `packages/aegis-vault-web/tsconfig.json` → `tsconfig.json`
- `packages/aegis-vault-web/dist/` → `dist/` (gitignored, rebuilt)
- `packages/aegis-vault-web/pkg/` → `pkg/` (gitignored, rebuilt)
- The `packages/` directory is removed. The Rust workspace stays at `crates/aegis-vault/`. If future framework adapters (Vue, Svelte, Solid) land as separate packages, they can go back under `packages/` without conflict — the primary `@cyberdione/aegis-vault-web` package just lives at the root.
- **`prepare` script now runs both `build:wasm` and `build:ts`** on install. Consumers that add aegis-vault as a git-URL dep get a fresh wasm + tsc build automatically (requires `cargo` + `wasm-pack` in PATH on the install machine). Runs once per install.
- Updated `scripts/build-wasm.sh` to output to `./pkg/` instead of `./packages/aegis-vault-web/pkg/`.
- Updated `.gitignore` to ignore `/pkg/` and `/dist/` at the root.

### Why
v0.2.0 used a monorepo-style subdirectory layout (`packages/aegis-vault-web/`) to reserve room for future framework-adapter packages. That layout broke npm git-URL installs because npm's git clone flow reads `package.json` from the clone root and has no subdirectory hint syntax. Consumers trying `"github:cyberdione/aegis-vault#v0.2.0"` got `ENOENT: no such file or directory, open '…/package.json'`.

The v0.3.0 reorg flattens the primary package to the root while keeping the Rust workspace at `crates/` and leaving space for future sibling packages. Consumers can now `npm install github:cyberdione/aegis-vault#v0.3.0` successfully.

### Content (unchanged from v0.2.0)
No API changes. The Rust crate, TypeScript sources, widget, React adapter, docs, and examples are byte-identical to v0.2.0 except for paths.

## [0.2.0] — 2026-04-08

### Added
- **Vanilla Web Component widget**: `<aegis-vault-modal>` custom element at `@cyberdione/aegis-vault-web/widget`. Framework-agnostic default UI for the unlock / create / ephemeral flow. Uses open shadow DOM for style encapsulation (not security — see `THREATMODEL.md`). Emits lifecycle custom events (`aegis-vault-unlocked`, `aegis-vault-locked`, `aegis-vault-created`, `aegis-vault-failed`, `aegis-vault-deleted`). Configurable via `hide-ephemeral` / `force-open` attributes and a `client` JS property for injecting alternative backends.
- **Transport-agnostic `VaultClient` interface** exported from `@cyberdione/aegis-vault-web/types`. Defines the contract that the current in-process backend (`AegisVault`) implements and that a future cross-origin iframe-host backend (Phase D) will also implement. Consumer code that types against the interface survives the transport swap unchanged.
- **Four runnable examples** in `docs/examples/`: `vanilla.html`, `vanilla-headless.html`, `react-with-widget.tsx`, `react-custom.tsx`. Documentation-as-code; not shipped in the npm package.
- **Phase D deployment path** documented in README and `THREATMODEL.md`: cross-origin iframe as the architecture that closes the "post-unlock same-origin JS" attack class.

### Changed — API (breaking, no consumers yet affected)
- `AegisVault.pageGet(name, key)` is now `Promise<string | null>` (was `string | null`).
- `AegisVault.pageEntries(name)` is now `Promise<Record<string, string>>` (was `Record<string, string>`).
- `AegisVault.identityOpen(purpose)` is now `Promise<IdentityHandleClient>` (was sync, returned raw wasm `IdentityHandle`).
- `IdentityHandleClient.pubkey` is now a **cached synchronous field** (was `pubkey(): Uint8Array`). Populated at open time.
- `IdentityHandleClient.sign(bytes)` is now `Promise<Uint8Array>` (was `Uint8Array`).
- `IdentityHandleClient.close()` is now `Promise<void>` (was `void`).
- All changes are the forward-compatibility contract for the Phase D cross-origin iframe transport. In-process resolution is still one microtask per call.
- `VaultProvider` in the React subpath now accepts `instance?: VaultClient` (was `instance?: AegisVault`). The narrower type was removed; the interface-typed parameter accepts both in-process and future iframe-host backends.

### Removed
- `@cyberdione/aegis-vault-web/react` no longer exports `VaultModal`. The reference React modal has been moved to `docs/examples/react-custom.tsx` as documentation-as-code. The library's React subpath is now hooks-only (`VaultProvider`, `useVault`, `useVaultState`). UI lives either in the new vanilla widget or in consumer code.

### Internal
- New file `packages/aegis-vault-web/src/types.ts` holds the `VaultClient` and `IdentityHandleClient` interfaces.
- New directory `packages/aegis-vault-web/src/widget/` contains the vanilla widget (`index.ts`, `modal.ts`, `state-machine.ts`, `styles.ts`).
- Rust crate unchanged. All 33 unit tests still pass.

### Naming
- Reminder: the term `anonymous` is deliberately absent from this codebase. See README §"Naming: avoiding `anonymous`".

## [0.1.0] — 2026-04-07

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
