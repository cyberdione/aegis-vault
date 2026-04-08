# Integration: hyprstream-rpc-std signing-path split

**Status:** proposed prerequisite, not yet implemented upstream.
**Target:** [`Hyprstream/crates/hyprstream-rpc-std/`](https://github.com/Hyprstream/) — the Rust source crate that cyberdione consumes via wasm-pack.
**Blocks:** cyberdione's integration of aegis-vault (the identity-layer fix for its per-session-random-keypair bug).

## Context

Cyberdione's browser-side RPC layer currently generates a **fresh random Ed25519 seed for every WASM RPC session** (`src/rpc/wasm-session.ts:40-55`). Because hyprstream-rpc-std's `RpcSession` holds its own signing key via `set_session_key(seed)` and signs envelopes internally via `sign_envelope_from_ptr(...)`, cyberdione's options today are:

1. Let hyprstream-rpc-std generate the seed (current behavior) — results in ~10 distinct signer pubkeys per tab, none persisted
2. Generate the seed in cyberdione and hand it to `set_session_key` — which is what aegis-vault replaces, but this still requires the seed to exist as a JS `Uint8Array` long enough to pass to the wasm call
3. **Split the signing path** so hyprstream-rpc-std never holds or sees the seed — this is the target

Option 3 is the right one. It turns hyprstream-rpc-std into a *signature-agnostic envelope builder*: it produces the canonical bytes that need to be signed, accepts a pre-computed signature from the caller, and wraps the pair into a Cap'n Proto `SignedEnvelope`. The seed lives in aegis-vault; hyprstream-rpc-std never touches it.

## What needs to change in `hyprstream-rpc-std`

Two new wasm-bindgen exports, replacing the existing `set_session_key` + `sign_envelope_from_ptr` pair:

### 1. `canonical_envelope_bytes`

```rust
/// Produce the canonical bytes that a caller must sign to build a
/// SignedEnvelope for this payload.
///
/// Does NOT sign anything. Does NOT touch key material. Pure function
/// over the payload, request_id, and optional streaming parameters.
///
/// The returned bytes are what the caller feeds to their signing oracle
/// (aegis-vault's `IdentityHandle::sign` for the browser, or a server-side
/// KMS for other consumers).
#[wasm_bindgen]
pub fn canonical_envelope_bytes(
    payload_ptr: usize,
    len: usize,
    request_id: u64,
    // Streaming-only fields, None for non-streaming:
    ephemeral_pubkey: Option<Vec<u8>>,
    jwt_token: Option<String>,
) -> Vec<u8>;
```

### 2. `build_signed_envelope_from_signature`

```rust
/// Wrap a payload, its pre-computed signature, and the signer's public
/// key into a Cap'n Proto SignedEnvelope ready for transport.
///
/// Does NOT sign anything. The `signature` must be 64 bytes (Ed25519)
/// and must have been produced over the output of `canonical_envelope_bytes`
/// with the same (payload, request_id, ...) inputs.
#[wasm_bindgen]
pub fn build_signed_envelope_from_signature(
    payload_ptr: usize,
    len: usize,
    request_id: u64,
    signature: Vec<u8>,          // 64 bytes Ed25519
    signer_pubkey: Vec<u8>,      // 32 bytes
    ephemeral_pubkey: Option<Vec<u8>>,
    jwt_token: Option<String>,
) -> Vec<u8>;
```

### 3. Remove (or deprecate for one release)

- `set_session_key(seed: &[u8])` — no longer needed; hyprstream-rpc-std has no seed to store
- `generate_signing_keypair()` — same; callers generate keys via their vault
- `sign_envelope_from_ptr(...)` — replaced by the `canonical_envelope_bytes` + `build_signed_envelope_from_signature` pair

A one-release deprecation window (mark `#[deprecated]`, keep functioning) is fine if there are other consumers of the crate beyond cyberdione. A hard remove is fine if cyberdione is the only consumer.

### 4. VfsShell::connect

Currently signature:

```rust
impl VfsShell {
    pub async fn connect(
        registry_url: &str,
        model_url: &str,
        cert_hash: Option<String>,
        seed: &[u8],          // ← raw 32-byte seed
    ) -> Result<VfsShell, JsValue>;
}
```

After: accept a signing callback or a handle ID that refers to an externally-held key. The cleanest shape is to let the caller inject a signing oracle via a JS function:

```rust
impl VfsShell {
    pub async fn connect(
        registry_url: &str,
        model_url: &str,
        cert_hash: Option<String>,
        signer_pubkey: Vec<u8>,              // 32 bytes Ed25519 public key
        sign_callback: js_sys::Function,     // (canonical_bytes) => Promise<Uint8Array>
    ) -> Result<VfsShell, JsValue>;
}
```

`sign_callback` is called every time VfsShell needs to sign an envelope; cyberdione wires it to `(bytes) => vault.identityOpen('vfs-shell-v1').then(h => h.sign(bytes))`. The VfsShell keeps the handle reference internally and never sees seed material.

## What this looks like from the cyberdione side

After the split lands, cyberdione's envelope signing becomes:

```ts
import { vault } from '@cyberdione/aegis-vault-web';
import * as hyprstream from '../wasm/hyprstream-rpc-std/hyprstream_rpc_std.js';

const handle = await vault.identityOpen('hyprstream-rpc-envelope-v1');

async function signedRpcCall(
  payloadPtr: number,
  payloadLen: number,
  requestId: bigint,
): Promise<Uint8Array> {
  // 1. Build the canonical bytes (pure, no keys)
  const canonical = hyprstream.canonical_envelope_bytes(
    payloadPtr, payloadLen, requestId, null, null,
  );

  // 2. Sign in the vault (seed never crosses this boundary)
  const signature = await handle.sign(canonical);

  // 3. Wrap into a SignedEnvelope with the signature (pure, no keys)
  const envelope = hyprstream.build_signed_envelope_from_signature(
    payloadPtr, payloadLen, requestId,
    signature,
    handle.pubkey,
    null, null,
  );

  return envelope;
}
```

Three wasm calls instead of one, but each is fast (microseconds), and the seed never leaves the vault's WASM linear memory as raw bytes. This is the property aegis-vault's threat model relies on for its identity-isolation claim.

## Why this needs to land upstream, not in cyberdione

The signing path is inside `hyprstream-rpc-std`'s Rust code. Cyberdione only consumes the compiled wasm-pack output; it cannot modify the signing logic without forking the crate. An upstream PR is the only way to make this change durable.

## Estimated impact

Rough guess based on reading the wasm-bindgen surface in `src/wasm/hyprstream-rpc-std/hyprstream_rpc_std.d.ts`:

- `lib.rs`: ~3 new wasm-bindgen exports (~100 LOC), ~3 deprecated exports (~30 LOC of `#[deprecated]` markers)
- `envelope.rs` (or wherever `SignedEnvelope` construction lives): split the existing `sign_envelope` into `canonical_envelope_bytes` + `build_signed_envelope_from_signature`. Should be straightforward — the canonical-bytes computation already exists inside the current sign function, it just needs to be exposed separately.
- `vfs_shell.rs`: change `connect` to accept a `js_sys::Function` signing callback instead of a seed. Medium-sized change — each place the shell signs something now needs to `.call1()` the callback and `await` the resulting Promise.
- Tests: add round-trip tests that build canonical bytes, sign externally, wrap with `build_signed_envelope_from_signature`, verify the resulting envelope.

**Estimated PR size: ~300-500 LOC added, ~50-100 LOC removed or deprecated.** Small by upstream standards.

## Testing the split

Cross-verification with the existing test suite:

1. For each hyprstream-rpc-std test that currently calls `sign_envelope_from_ptr`, add a parallel test that calls `canonical_envelope_bytes` → (sign externally with the same seed via a test helper) → `build_signed_envelope_from_signature`. The resulting envelope bytes must be identical.
2. Server-side acceptance: point a test hyprstream server at an envelope built via the new path. It should verify and process identically.
3. VfsShell round-trip: call `VfsShell::connect` with a dummy signing callback that uses a fixed test seed; verify that RPCs still work end-to-end.

## Sequencing

1. **Phase A.0 (this doc)** — land the split in `Hyprstream/crates/hyprstream-rpc-std/`, release as `hyprstream-rpc-std 0.X+1`
2. **Phase A.2** — cyberdione updates its `scripts/build-wasm.sh` to fetch the new version, wires the new exports into `wasm-session.ts` / `client.ts` / `HyprstreamRpcContext.tsx`, wraps the provider tree in `<VaultProvider>`, migrates `AuthContext` + `HyprstreamHostContext` from localStorage to vault pages. See cyberdione's internal plan at `~/.claude/plans/atomic-wandering-stroustrup.md` for the full wire-up list.

Phase A.0 is the upstream blocker. Until it lands, cyberdione can install `@cyberdione/aegis-vault-web` as a dep and use it for page storage (LLM secrets, OAuth tokens), but cannot move the signing identity into the vault.

## What this does NOT require

- No changes to aegis-vault itself. The v0.2.0 API is already designed around `handle.sign(canonical_bytes)` being the only signing entry point; this plan just connects it to hyprstream-rpc-std's existing envelope construction.
- No changes to the hyprstream server or wire format. The `SignedEnvelope` on the wire is byte-identical to what hyprstream-rpc-std produces today — only the code path that *constructs* it has been split in two.
- No changes to Cap'n Proto schemas.
- No changes to the WebTransport / ZMTP transport layer.
- No new dependencies in hyprstream-rpc-std.

## Alternative: keep hyprstream-rpc-std's seed, inject via vault.identitySeed()

An earlier version of the aegis-vault plan considered adding a `vault.identitySeed(purpose)` method that returns raw bytes, which the cyberdione side would then pass to `set_session_key`. **That path is rejected.** It defeats the "seed never leaves the vault" property and defeats the HSM API design. If hyprstream-rpc-std cannot be split, we stay with today's per-session random keys for signing and only use the vault for page storage — which still fixes the localStorage exfiltration problem but leaves the identity problem unsolved.

Splitting hyprstream-rpc-std is the correct architectural move regardless of aegis-vault; the crate's signing function should not mix key material with envelope construction.

## Open questions

1. **Is `hyprstream-rpc-std` open to an upstream PR from the cyberdione side?** If yes, who reviews. If no, cyberdione forks or patches the crate (which is worse for maintenance but works).
2. **Other consumers of `set_session_key` / `sign_envelope_from_ptr`?** If hyprstream itself (server-side tooling, CLI, tests) uses those functions, the deprecation window matters. If cyberdione is the only consumer, we can hard-remove.
3. **VfsShell's internal signing frequency.** How many envelopes does a typical shell session build? The sign-callback path adds one `js_sys::Function::call1 → await JsFuture → Uint8Array` round trip per envelope. If VfsShell builds hundreds of envelopes per second, that's fine in-process (microsecond-ish); in Phase D's iframe transport it becomes a real concern and may motivate batching.
