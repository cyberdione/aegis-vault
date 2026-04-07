# aegis-vault

> Encrypted browser identity vault. Passphrase + WebAuthn-PRF, AES-256-GCM at rest, HSM-shaped per-purpose Ed25519 signing slots.

A browser-side secret store designed to replace plaintext `localStorage` for OAuth refresh tokens, host configurations, and identity material — and to replace per-session random keypairs with a stable browser identity that persists across reloads. The Ed25519 signing seed lives in WebAssembly linear memory and is **never returned to JavaScript** as raw bytes; consumers obtain opaque `IdentityHandle`s and ask the vault to sign on their behalf.

**Status:** v0.1, API not stable until 1.0.

## Why

Modern browser apps that talk to authenticated backend services typically store:

- **OAuth refresh tokens** — long-lived bearer credentials
- **Per-host config** — endpoint URLs, cert hashes, OAuth client IDs
- **Per-session signing keys** — frequently regenerated random Ed25519 seeds, one per service

In `localStorage`, all of these are readable by any browser extension with content-script access and any XSS payload that lands in the tab. The signing keys, when generated fresh per session, also prevent the server from recognizing the same browser across reloads — defeating audit, capability, and rate-limiting based on signer pubkey.

Aegis-vault fixes both:

1. **Encryption at rest in IndexedDB**, AES-256-GCM with subkeys derived per page from a passphrase-protected master key (Argon2id + HKDF). Optional WebAuthn PRF as a hardware second factor.
2. **Persistent identity slots**, derived deterministically per "purpose" string from the vault's root seed via HKDF. The hyprstream signing identity, the SSH signing identity, and the git-commit-signing identity are independent keypairs that all derive from the same vault.
3. **HSM-shaped signing API**: the seed never leaves the wasm module. Consumers receive `IdentityHandle`s and call `handle.sign(canonical_bytes)`. There is no `seed()` or `export_seed()` accessor in the default profile.

## Install

```bash
npm install @cyberdione/aegis-vault-web
```

For local development against a sibling clone (no `file://` paths needed):

```bash
# Cargo override (if a Rust consumer ever wants the crate directly)
[patch."https://github.com/cyberdione/aegis-vault"]
aegis-vault = { path = "../aegis-vault/crates/aegis-vault" }

# npm override
npm link @cyberdione/aegis-vault-web
# or in package.json:
# "@cyberdione/aegis-vault-web": "github:cyberdione/aegis-vault#main"
```

## Quick start

```ts
import { vault, type IdentityHandle } from '@cyberdione/aegis-vault-web';

// 1. Check if a vault exists; if not, create one.
if (!(await vault.exists())) {
  await vault.create('correct horse battery staple');
} else {
  await vault.unlock('correct horse battery staple');
}

// 2. Open an identity for a stable purpose.
const id: IdentityHandle = vault.identityOpen('hyprstream-rpc-envelope-v1');

// 3. The pubkey is stable across reloads for this passphrase + purpose.
const pubkey: Uint8Array = id.pubkey();

// 4. Sign canonical bytes. Domain separation is enforced inside the vault.
const canonical = new Uint8Array([1, 2, 3, 4]);
const signature: Uint8Array = id.sign(canonical);

// 5. Persist OAuth tokens encrypted at rest.
await vault.pageSet('auth', 'refresh_token_host_a', '...');
await vault.pageSet('auth', 'client_id_host_a', '...');

// 6. On reload + unlock, the same purpose returns the same key.
```

## Persistence model: two booleans, no enum

A vault is in one of three observable states, exposed as **two independent booleans**:

| `locked` | `persistent` | Meaning |
|---|---|---|
| `true` | _ignored_ | No in-memory vault. UI should show an unlock modal. |
| `false` | `true` | Vault loaded from (or created into) IndexedDB. `pageSet` writes survive reload. |
| `false` | `false` | Ephemeral in-memory vault. `pageSet` writes are lost on reload. |

```ts
import { vault } from '@cyberdione/aegis-vault-web';

vault.subscribe(({ locked, persistent }) => {
  console.log({ locked, persistent });
});

await vault.create('passphrase');         // → { locked: false, persistent: true }
await vault.startEphemeral();             // → { locked: false, persistent: false }
vault.lock();                             // → { locked: true,  persistent: false }
```

There is no `mode` enum and no string state. Consumers that need to know whether their `pageSet` calls will persist should check `vault.persistent` before writing.

## Naming: avoiding `anonymous`

Hyprstream (one of this vault's intended consumers) has a server-side `Subject` named `anonymous`, meaning "this request carried no JWT identity claim." That is **not** the same thing as a vault that holds an in-memory ephemeral root seed without persisting it to disk:

- A vault with `persistent: false` can still authenticate to hyprstream as `Subject: jane@example.com` (the user is OAuth-logged-in, the JWT is sent, the server logs `jane`).
- A fully persistent vault with no JWT loaded appears as `Subject: anonymous` to hyprstream.

To prevent the two concepts from blurring in code review and incident response, **aegis-vault never uses the word `anonymous`** in any identifier, type name, comment, log line, or UI string. The Rust constructor for an in-memory vault is `Vault::ephemeral()`. The TS API method is `vault.startEphemeral()`. The reference modal button copy is "Continue without saving." If you see `anonymous` in an aegis-vault PR, please reject it on naming grounds.

## HSM-style identity slots

The vault is shaped like a hardware security module: keys live inside the vault, operations on those keys go through the vault, and key material is not exported.

```ts
const id = vault.identityOpen('hyprstream-rpc-envelope-v1');
//                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                              "purpose" — a stable string identifier.
//                              Each unique purpose derives an independent
//                              Ed25519 keypair via HKDF from the root seed.

id.pubkey();   // 32 bytes — stable across reloads for the same passphrase
id.sign(...);  // 64 bytes — Ed25519 signature, domain-separated by purpose
```

### Per-purpose key derivation

For each `purpose` string, the vault computes:

```
purpose_seed = HKDF-SHA256(
    ikm  = root_seed,
    info = "aegis-purpose-key-v1\0" || purpose
)
signing_key  = Ed25519::from_seed(purpose_seed)
```

Two different purposes (`"hyprstream-rpc-envelope-v1"` and `"ssh-user-cert-v1"`) produce cryptographically independent keypairs. Compromise of one purpose's signing oracle does not weaken the others. Privacy benefit: an observer of one server's signer pubkey cannot link the user to a different server's signer pubkey.

### Domain-separated signing

Every `sign()` call is over a SHA-512 prehash that binds the purpose:

```
signed_bytes = SHA-512(
    "aegis-purpose-v1\0"
    || (purpose_length as u8)
    || purpose
    || canonical_bytes
)
signature = Ed25519::sign(purpose_signing_key, signed_bytes)
```

A signature produced under purpose A will **not verify** against purpose B's pubkey, even for byte-identical `canonical_bytes`. This makes cross-protocol attacks (one purpose's signing oracle producing valid signatures for another purpose's protocol) structurally impossible.

### Verifying signatures server-side

A verifier needs to replicate the prehash and check against the per-purpose pubkey. Pseudocode:

```python
def verify(pubkey, purpose, canonical_bytes, signature):
    prehash = sha512(
        b"aegis-purpose-v1\0"
        + bytes([len(purpose)])
        + purpose.encode("utf-8")
        + canonical_bytes
    )
    return ed25519_verify(pubkey, prehash, signature)
```

The `aegis-vault` Rust crate exposes a `verify_purpose` test helper for round-trip checks; production verifiers should implement the prehash construction directly to avoid taking on a vault dependency.

## Pages: encrypted key/value storage

Pages are independently encrypted namespaces within the vault. Each page has its own AES-256-GCM subkey derived from the root seed via HKDF.

```ts
await vault.pageSet('auth', 'refresh_token', 'abc...');
await vault.pageSet('auth', 'client_id', 'xyz...');
await vault.pageSet('hosts', 'host:host_42', JSON.stringify({...}));

const token = vault.pageGet('auth', 'refresh_token');
const allAuth = vault.pageEntries('auth');
```

### Well-known page names

The crate validates against a fixed list of page names so the on-disk `page_id` byte stays stable across consumers. v0.1 supports:

| Page | Intended use |
|---|---|
| `hosts` | Host endpoints, cert hashes, OAuth URLs |
| `auth` | OAuth refresh tokens, dynamic client IDs |
| `llm` | LLM provider API keys |
| `prefs` | App preferences and small config |

Adding a new well-known page requires bumping the crate version and adding a `PageId` variant. Future versions may relax this if free-form page names prove safe.

## React integration

```tsx
import { VaultProvider, useVault, VaultModal } from '@cyberdione/aegis-vault-web/react';

function App() {
  return (
    <VaultProvider>
      <VaultModal />              {/* shown automatically when locked */}
      <YourApp />
    </VaultProvider>
  );
}

function YourApp() {
  const { state, actions } = useVault();
  if (state.locked) return null;  // VaultModal handles this case
  // ...
}
```

The `VaultModal` is a minimal, unstyled reference implementation. Real apps should build their own modal using `useVault()` and pair it with their UI library (Chakra, shadcn, Tailwind, etc).

## Architecture

```
┌────────────────────────────────────────┐
│  Your app (React, vanilla JS, Vue…)    │
└──────────────┬─────────────────────────┘
               │  TypeScript
┌──────────────▼─────────────────────────┐
│  @cyberdione/aegis-vault-web           │
│  - AegisVault (locked / persistent)    │
│  - IndexedDB I/O                       │
│  - BroadcastChannel tab sync           │
│  - VaultProvider, useVault             │
└──────────────┬─────────────────────────┘
               │  wasm-bindgen
┌──────────────▼─────────────────────────┐
│  aegis-vault (Rust crate)              │
│  - Argon2id, HKDF, AES-GCM, HMAC       │
│  - Ed25519 per-purpose derivation      │
│  - Page encrypt/decrypt                │
│  - Versioned blob format               │
│  - Zeroizing<...> for all secrets      │
└────────────────────────────────────────┘
```

The Rust crate is the only place that handles secrets. The TS shim shuttles opaque ciphertext blobs between IDB and the wasm module, but never sees plaintext seeds, page contents, or signatures-in-progress.

## Build from source

```bash
git clone https://github.com/cyberdione/aegis-vault
cd aegis-vault

# Build the Rust crate to wasm
cd packages/aegis-vault-web
npm install
npm run build:wasm

# Compile the TS shim
npm run build:ts
```

Or all at once: `npm run build`.

Tests:

```bash
# Rust unit tests (native target)
cd crates/aegis-vault
cargo test
```

## Phase B (future)

This package is the in-process wasm-bindgen variant. A future Phase B will compile the same Rust core to a WASI binary that runs as an isolated [Wanix](https://github.com/cyberdione/wanix) process, communicating with consumer code via DMA ring buffer IPC. In that mode, the seed lives in a separate WebAssembly linear memory that the main thread cannot read at all, closing the only remaining seed-exposure path. The same TypeScript API is preserved — only the transport changes.

Phase B is not part of v0.1 and will land as a separate release once Wanix integration prerequisites are in place.

## License

Apache-2.0. See `LICENSE`.

## Threat model

See [`THREATMODEL.md`](./THREATMODEL.md) for what aegis-vault protects against and what it explicitly does not.
