# aegis-vault

> Encrypted browser identity vault. Passphrase + WebAuthn-PRF, AES-256-GCM at rest, HSM-shaped per-purpose Ed25519 signing slots.

A browser-side secret store designed to replace plaintext `localStorage` for OAuth refresh tokens, host configurations, and identity material — and to replace per-session random keypairs with a stable browser identity that persists across reloads. The Ed25519 signing seed lives in WebAssembly linear memory and is **never returned to JavaScript** as raw bytes; consumers obtain opaque `IdentityHandle`s and ask the vault to sign on their behalf.

The library is a **vanilla TypeScript / ECMAScript library**. It ships with an optional vanilla Web Component widget (`<aegis-vault-modal>`) for the default UI, and an optional thin React adapter for React consumers. Neither is required — you can always drop down to the headless core API and build your own UI.

**Status:** v0.2, API not stable until 1.0.

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

## Quick start — vanilla widget (easiest)

Drop the element into your HTML and listen for its events. Works in plain HTML, React, Vue, Svelte, Solid, or anything else.

```html
<script type="module">
  // Side-effect import: registers <aegis-vault-modal>
  import '@cyberdione/aegis-vault-web/widget';
  import { vault } from '@cyberdione/aegis-vault-web';

  const modal = document.querySelector('aegis-vault-modal');
  modal.addEventListener('aegis-vault-unlocked', async (ev) => {
    // ev.detail: { persistent: boolean }
    const id = await vault.identityOpen('my-app-v1');
    console.log('signer pubkey:', id.pubkey);
    const sig = await id.sign(new TextEncoder().encode('hello'));
    await id.close();
  });
</script>

<aegis-vault-modal></aegis-vault-modal>
```

See [`docs/examples/vanilla.html`](docs/examples/vanilla.html) for a complete runnable example.

## Quick start — vanilla headless (build your own UI)

For full control over the modal UX, skip the widget and talk to the core API directly:

```ts
import { vault } from '@cyberdione/aegis-vault-web';

// 1. Check if a vault exists; if not, create one.
if (!(await vault.exists())) {
  await vault.create('correct horse battery staple');
} else {
  await vault.unlock('correct horse battery staple');
}

// 2. Open an identity for a stable purpose.
const id = await vault.identityOpen('hyprstream-rpc-envelope-v1');

// 3. The pubkey is stable across reloads for this passphrase + purpose.
const pubkey: Uint8Array = id.pubkey;  // cached, synchronous access

// 4. Sign canonical bytes. Domain separation is enforced inside the vault.
const canonical = new Uint8Array([1, 2, 3, 4]);
const signature: Uint8Array = await id.sign(canonical);

// 5. Persist OAuth tokens encrypted at rest.
await vault.pageSet('auth', 'refresh_token_host_a', '...');
await vault.pageSet('auth', 'client_id_host_a', '...');

// 6. On reload + unlock, the same purpose returns the same key.
await id.close();
```

See [`docs/examples/vanilla-headless.html`](docs/examples/vanilla-headless.html) for a complete runnable example that builds its own modal.

## Quick start — React

React consumers can either use the widget directly inside JSX (React treats lowercase tags as custom elements):

```tsx
import '@cyberdione/aegis-vault-web/widget';
import { vault } from '@cyberdione/aegis-vault-web';

function App() {
  return (
    <>
      <aegis-vault-modal />
      <YourApp />
    </>
  );
}
```

Or build a custom modal with the headless `useVault()` hook:

```tsx
import { VaultProvider, useVault } from '@cyberdione/aegis-vault-web/react';

function App() {
  return (
    <VaultProvider>
      <VaultGate><AuthedApp /></VaultGate>
    </VaultProvider>
  );
}

function VaultGate({ children }) {
  const { state, actions } = useVault();
  if (state.locked) return <YourCustomModal onUnlock={actions.unlock} />;
  return children;
}
```

See [`docs/examples/react-with-widget.tsx`](docs/examples/react-with-widget.tsx) and [`docs/examples/react-custom.tsx`](docs/examples/react-custom.tsx) for complete examples.

## Async API contract

**All cross-boundary vault methods are `async`**, even though the current in-process backend resolves synchronously underneath. This is a forward-compatibility contract: a future cross-origin iframe deployment ([Phase D](#phases)) will use the same interface but round-trip each call through `postMessage`. Keeping consumer code async-shaped from day one means the transport swap is invisible.

In practice: `pageGet`, `pageEntries`, `identityOpen`, `IdentityHandle.sign`, and `IdentityHandle.close` all return `Promise`s. The exceptions are `IdentityHandle.pubkey` (cached at open time, synchronous field access) and `lock()` (fire-and-forget local zeroize).

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

To prevent the two concepts from blurring in code review and incident response, **aegis-vault never uses the word `anonymous`** in any identifier, type name, comment, log line, or UI string. The Rust constructor for an in-memory vault is `Vault::ephemeral()`. The TS API method is `vault.startEphemeral()`. The widget button copy is "Continue without saving." If you see `anonymous` in an aegis-vault PR, please reject it on naming grounds.

## HSM-style identity slots

The vault is shaped like a hardware security module: keys live inside the vault, operations on those keys go through the vault, and key material is not exported.

```ts
const id = await vault.identityOpen('hyprstream-rpc-envelope-v1');
//                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                                    "purpose" — a stable string identifier.
//                                    Each unique purpose derives an independent
//                                    Ed25519 keypair via HKDF from the root seed.

id.pubkey;            // 32 bytes — cached at open, synchronous field access
await id.sign(bytes); // 64 bytes — Ed25519 signature, domain-separated by purpose
await id.close();
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

const token = await vault.pageGet('auth', 'refresh_token');
const allAuth = await vault.pageEntries('auth');
```

All page operations are async. See "Async API contract" above for why.

### Well-known page names

The crate validates against a fixed list of page names so the on-disk `page_id` byte stays stable across consumers. v0.2 supports:

| Page | Intended use |
|---|---|
| `hosts` | Host endpoints, cert hashes, OAuth URLs |
| `auth` | OAuth refresh tokens, dynamic client IDs |
| `llm` | LLM provider API keys |
| `prefs` | App preferences and small config |

Adding a new well-known page requires bumping the crate version and adding a `PageId` variant. Future versions may relax this if free-form page names prove safe.

## Architecture

```
┌─────────────────────────────────────────────┐
│  Your app (vanilla, React, Vue, Svelte, …)  │
└──────────────┬──────────────────────────────┘
               │  one of three paths
   ┌───────────┼────────────────────────┐
   │           │                        │
   ▼           ▼                        ▼
┌────────┐ ┌──────────────────┐  ┌─────────────┐
│ widget │ │ headless TS API  │  │ react hooks │
│ (vanilla │ │ (vanilla)        │  │ (~80 LOC    │
│  Web     │ │ vault singleton  │  │  adapter)   │
│  Comp)   │ │ VaultClient iface│  │             │
└────┬───┘ └────────┬─────────┘  └─────┬───────┘
     └──────────────┴──────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│  @cyberdione/aegis-vault-web (vanilla core) │
│  - AegisVault (locked / persistent)         │
│  - IndexedDB I/O                            │
│  - BroadcastChannel tab sync                │
│  - Async VaultClient contract               │
└──────────────┬──────────────────────────────┘
               │  wasm-bindgen
┌──────────────▼──────────────────────────────┐
│  aegis-vault (Rust crate)                   │
│  - Argon2id, HKDF, AES-GCM, HMAC            │
│  - Ed25519 per-purpose derivation           │
│  - Page encrypt/decrypt                     │
│  - Versioned blob format                    │
│  - Zeroizing<...> for all secrets           │
└─────────────────────────────────────────────┘
```

The Rust crate is the only place that handles secrets. The TS core shuttles opaque ciphertext blobs between IDB and the wasm module but never sees plaintext seeds, page contents, or signatures-in-progress. The three consumption paths (widget, headless, React hooks) are thin layers over the vanilla core — you can mix and match, and switching between them is a one-import change.

React is not privileged in the architecture. Future Vue / Svelte / Solid adapters would be peers of the React adapter, all built on the same vanilla `VaultClient` interface.

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

## Phases

This repo delivers aegis-vault in phases. v0.2 is the current release.

### Shipped

- **v0.1** — Rust crate + TS shim + React hooks, in-process backend only. Bootstrapped the project.
- **v0.2** (current) — Vanilla `<aegis-vault-modal>` Web Component widget. Async API contract (`pageGet`, `identityOpen`, `IdentityHandle.sign` all `Promise`-returning). Transport-agnostic `VaultClient` interface. React modal reference implementation moved from library code into `docs/examples/` so the React subpath is purely headless hooks.

### Future

- **Phase B — Wanix worker isolation.** Compile the same Rust core to a WASI binary that runs as an isolated [Wanix](https://github.com/cyberdione/wanix) process, communicating with consumer code via DMA ring buffer IPC. The seed lives in a separate WebAssembly linear memory that the main thread cannot read at all. Same `VaultClient` interface; only the transport changes.

- **Phase D — Cross-origin iframe deployment.** Serve the vault as a static iframe-guest app at a separate origin (e.g. `vault.cyberdione.io`). Parent pages embed it with `<iframe>` and talk over `postMessage`; the same-origin policy provides a real isolation boundary against post-unlock JavaScript in the host page. Same `VaultClient` interface — a new `/iframe-host` subpath implements it by routing calls through `postMessage`. Phase B and Phase D compose: the iframe-guest can internally run the vault in a Wanix worker for maximum strength.

Neither is part of v0.2. Both are tracked in the aegis-vault roadmap and will land as separate releases. Phase D is expected to land before Phase B because it's an independently valuable deployment option and does not depend on Wanix bring-up.

## License

Apache-2.0. See `LICENSE`.

## Threat model

See [`THREATMODEL.md`](./THREATMODEL.md) for what aegis-vault protects against and what it explicitly does not.
