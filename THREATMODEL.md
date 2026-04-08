# Aegis-vault threat model (v0.1)

This document describes what aegis-vault is designed to protect against, what it explicitly does not, and the trade-offs we accept in v0.1. **Read it before deploying.** A vault library that misrepresents its threat model is worse than no vault at all.

## Assumptions

The vault is deployed in a modern browser (Chrome / Firefox / Safari current). We assume:

- The browser's WebCrypto, IndexedDB, and `crypto.getRandomValues` implementations are not actively malicious. (If they are, no browser-side vault can save you.)
- The TLS connection delivering the vault wasm and the host page is not under attacker MitM. SRI on the wasm artifact is the right mitigation against compromised CDN; that lives at the consumer level, not in this package.
- The user's passphrase is reasonably strong. Argon2id at our parameters tolerates moderate entropy but is not a substitute for a passphrase generator.
- The host page is not currently executing attacker JavaScript. Once an attacker has post-unlock JS execution in the same origin, no in-process vault can stop them; see "Not protected against" below.

## Protected against

### Passive disk capture
A device that is later stolen, imaged, or seized: the IndexedDB blobs are AES-256-GCM ciphertext keyed under an Argon2id-derived master key (memory cost m=19 MiB, time cost t=2). An offline brute-force is bottlenecked by Argon2id, which is the entire point of choosing it. Even with a strong adversary GPU farm, weak passphrases will fall first; strong passphrases (24+ random chars) remain infeasible.

### Plaintext localStorage extraction
The legacy attack surface this vault is designed to replace. Refresh tokens, OAuth client IDs, host configurations, and LLM API keys move from `localStorage` (synchronous, indexable, accessible to any same-origin script) to encrypted IDB blobs that are useless without the passphrase. This is the largest single security improvement v0.1 delivers.

### Content-script extension exfiltration
A malicious browser extension with content-script access to the origin can read `localStorage` directly via `window.localStorage`. After migration to aegis-vault, the same extension can only read encrypted IDB blobs — useless without the passphrase. The extension can still observe vault operations *while the user is unlocked* (see "Not protected against") but cannot recover state from before extension installation, and cannot persist stolen state past a page reload.

### Cross-site scripting that lands in dormant pages
An XSS payload that fires on a page where the user has not unlocked the vault sees no in-memory state. The vault is locked by default at every page load — there is no "auto-unlock" surface. The XSS is reduced to a denial-of-service.

### Server impersonation by signer pubkey
With a stable per-purpose Ed25519 identity, the server can audit, rate-limit, and assign capabilities by `signerPubkey`. Today's per-session-random keys defeat all of these. After aegis-vault, the same browser produces the same pubkey across reloads, enabling honest server-side identity binding.

### Cross-protocol signature confusion
Domain separation: every signature is over `SHA-512(purpose_tag || canonical_bytes)`. A signing oracle for purpose A cannot be coerced into producing valid signatures for purpose B's wire format, even with byte-identical canonical input. Cross-protocol attacks are structurally impossible.

### AEAD tampering
All ciphertext (root seed, every page) is AES-256-GCM with the page header bound as AAD. Any bit flip in the stored blob — header byte, IV, ciphertext, tag — fails decryption. There is no plaintext recovery path that bypasses authentication.

### WebAuthn-PRF as a hardware second factor
When enrolled, the vault requires *both* the passphrase *and* the hardware authenticator's PRF output to derive the meta key. Losing the hardware token (or the passphrase) makes the vault unrecoverable. There is no recovery code in v0.1; this is by design and disclosed in the README.

## Not protected against

### Post-unlock in-process JavaScript
**This is the most important caveat.** Once the user has unlocked the vault, an attacker who achieves JavaScript execution in the same origin can:

1. Call `await vault.identityOpen('hyprstream-rpc-envelope-v1').then(h => h.sign(arbitrary_bytes))` and obtain a valid signature for whatever bytes they choose. Domain separation prevents *cross*-purpose forgery, but the attacker can still forge for the same purpose.
2. Read pages via `await vault.pageEntries('auth')` and recover refresh tokens.
3. Hold references to `IdentityHandleClient` objects across `vault.lock()` calls.
4. **Bypass the Web Component widget entirely.** Shadow DOM is encapsulation, not isolation (see next section).

The vault is **not** a hardware security module and cannot stop in-process attackers. **Phase D (cross-origin iframe deployment)** is the architecture that closes this path structurally: when the vault is served from a separate origin (e.g. `vault.cyberdione.io`) and embedded as an iframe, the same-origin policy enforces a real JavaScript isolation boundary. Phase B (Wanix worker isolation) complements that by closing in-origin leakage as well. Both are future work. v0.2 is a substantial improvement over the localStorage status quo but does not claim to defend against compromised same-origin JavaScript when deployed in-process.

### Widget shadow DOM is NOT a security boundary
The `<aegis-vault-modal>` Web Component uses an open shadow root for style encapsulation, event scoping, and framework agnosticism. **Closed shadow DOM is also not a security boundary** and we deliberately use open mode because closed adds no real security and breaks accessibility tooling.

Same-origin JavaScript trivially bypasses shadow DOM in several routine ways:

- Override `Element.prototype.attachShadow` before the widget loads; capture every shadow root the widget creates.
- Override `EventTarget.prototype.addEventListener` to wrap and log every keystroke handler.
- Listen on `document` with `{ capture: true }` for keyboard events that propagate through the shadow boundary during the capture phase.
- Patch `crypto.subtle`, `IndexedDB.open`, or any global the widget calls into.

**Treat the widget as a convenience and trust upgrade, not an isolation primitive.** Its real benefits are: style isolation from the host page's CSS, a framework-agnostic drop-in component, and a single trusted reference UI that consumers don't have to re-implement. If you need isolation against same-origin JavaScript, use the cross-origin iframe deployment (Phase D).

### Memory dumping the WebAssembly linear memory
The seed is held in `Zeroizing<[u8; 32]>` inside the wasm module's linear memory. Anything with `wasm.memory.buffer.subarray(...)` access can read it raw. In the in-process binding, the wasm memory buffer is accessible from any same-origin JS — see the previous point. Phase B's process boundary is the structural fix.

### Side channels (timing, cache, memory access patterns)
The underlying RustCrypto primitives are constant-time-ish on native, but the WebAssembly JIT does not guarantee constant-time execution. Browser-level mitigations (SharedArrayBuffer cross-origin isolation, JIT spraying defenses) help but are not enough for high-value targets. We do not claim defense against motivated side-channel attackers.

### Tampering with the vault wasm itself
A compromised CDN or build pipeline that ships a malicious wasm module can do anything. The mitigation is Subresource Integrity (SRI) on the wasm asset, applied at the consumer level, plus reproducible builds. Both are out of scope for v0.1; v0.2 may add npm provenance / signed releases.

### Coerced unlock by the user themselves
If the user is under duress and types their passphrase, the vault unlocks. Plausible deniability features (ephemeral mode, hidden vaults) are not in v0.1.

### Cross-device sync
v0.1 is single-browser. Two devices each maintain their own vault. The blob format is forward-compatible (versioned, monotonic counters) for a future sync layer, but no transport ships in v0.1.

### Backups / recovery
None. Lost passphrase = lost vault. Documented in the README; consumers should warn users at create time.

### Multiple vaults per browser (work / personal split)
v0.1 supports one vault per origin. Multi-vault is a v2 feature.

### Per-operation user presence (WebAuthn touch on every signature)
WebAuthn PRF is used at *unlock* time only. Each individual `sign()` call does not require a fresh authenticator touch. A future release may add per-slot policies that gate operations on a fresh assertion.

## Deployment options and the threat model upgrade path

v0.2 ships the in-process wasm-bindgen backend. Two future deployment options give stronger properties without changing the consumer-facing API:

### Phase D — Cross-origin iframe
Serve the aegis-vault wasm + unlock widget at a separate origin (e.g. `vault.cyberdione.io`) and embed it in the host page as an `<iframe>`. The parent page cannot:
- Read keystrokes typed into the vault's passphrase input
- Inspect the DOM of the iframe
- Run JavaScript in the iframe's realm
- Override prototypes or intercept `crypto.subtle` calls inside the iframe
- Access the vault's IndexedDB partition (it's partitioned per origin)

Communication happens over `postMessage`, so every `handle.sign(bytes)` call is an RPC round-trip. The host page sees only `{ signature }` results, never key material. **This is the same architecture Stripe Elements, Plaid Link, Google Sign-In, and PayPal credential prompts use for exactly this reason.**

Phase D requires a deployment change (a new origin) but no API change. Consumer code written against `VaultClient` today will work unchanged — only the import line changes from `@cyberdione/aegis-vault-web` to `@cyberdione/aegis-vault-web/iframe-host`.

### Phase B — Wanix worker isolation
Run the vault Rust core as a WASI binary inside a Wanix worker process. Even within a single origin, the main thread and the vault have separate WebAssembly linear memories. `Phase B + Phase D` combined is the strongest deployment: a cross-origin iframe containing a Wanix worker, isolated at both boundaries.

### What each phase closes

| Attack class                                | v0.2 (in-process) | Phase D (iframe) | Phase B (wanix) | B + D |
|---|---|---|---|---|
| Disk capture at rest                        | ✅ protected        | ✅                | ✅              | ✅     |
| localStorage scraping                       | ✅ protected        | ✅                | ✅              | ✅     |
| Cross-protocol forgery                      | ✅ protected        | ✅                | ✅              | ✅     |
| Post-unlock JS in host page                 | ❌ not protected    | ✅ protected       | partial         | ✅     |
| Post-unlock JS in vault origin              | ❌ not protected    | ❌ not protected   | ✅ protected    | ✅     |
| WebAssembly memory dump by same-origin JS   | ❌ not protected    | ✅ protected       | ✅ protected    | ✅     |

The jump from v0.2 to Phase D is the most valuable single upgrade because it closes the entire "post-unlock JS in host page" class. Phase D is a deployment-configuration change with zero Rust changes and zero consumer API changes; Phase B requires Wanix runtime integration and is the harder prerequisite.

## Cryptographic parameters

For audit and external review, here are the locked v0.2 parameters:

| Primitive | Algorithm | Parameters |
|---|---|---|
| KDF | Argon2id (RFC 9106) | m = 19,456 KiB, t = 2, p = 1, output = 32 bytes |
| Master/page key derivation | HKDF-SHA256 (RFC 5869) | salt = 32-byte zero (extract-then-expand from already-uniform IKM) |
| Symmetric AEAD | AES-256-GCM | 96-bit IV (random per write), 128-bit tag |
| MAC (passphrase × WebAuthn combine) | HMAC-SHA256 | RFC 2104 |
| Signature | Ed25519 (RFC 8032) | dalek implementation, prehash via SHA-512 |
| ECDH (reserved, not exposed in v0.1) | X25519 | dalek implementation |
| RNG | `crypto.getRandomValues` via `getrandom` crate | platform browser RNG |

KDF parameters are deliberately tuned to take ~500ms-1s on a midrange laptop in browser WASM, matching the Onion Shell vault tuning. Faster parameters reduce per-guess cost; slower parameters annoy users. v0.2 may make this user-configurable at create time.

## Audit status

**Unaudited.** v0.1 is a clean-room implementation against well-known primitives from the RustCrypto and dalek-cryptography ecosystems. It has no third-party security audit. Production deployment in adversarial environments should commission an audit first.

## Reporting vulnerabilities

Email security@cyberdione.io (or open a private security advisory on the GitHub repository). Do not file public issues for security bugs.
