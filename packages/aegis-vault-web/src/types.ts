/**
 * Transport-agnostic client interfaces.
 *
 * Defines the contract that both the in-process backend (v0.1+, this package)
 * and the future cross-origin iframe-host backend (v1.0, Phase D) implement.
 *
 * **All cross-boundary operations are async from day one**, even when the
 * in-process backend resolves synchronously underneath. This is the design
 * contract that lets us swap the transport to a postMessage RPC layer later
 * without breaking any consumer code. See README §"Async API contract".
 *
 * Consumer code should import `VaultClient` from here rather than referring
 * to the concrete `AegisVault` class — staying interface-typed keeps the
 * upgrade to the iframe transport a one-line import change.
 */

/**
 * Observable state. Two independent booleans, no enum.
 *
 * - `locked: true`  — no in-memory vault. UI should show an unlock modal.
 * - `locked: false, persistent: true`  — persistent vault, writes survive reload.
 * - `locked: false, persistent: false` — ephemeral vault, writes lost on reload.
 *
 * The fourth combination is impossible. See README §"Persistence model".
 */
export interface VaultState {
  locked: boolean;
  persistent: boolean;
}

/** Listener type for `subscribe`. */
export type VaultStateListener = (state: VaultState) => void;

/**
 * The top-level vault client interface. Implemented by:
 *   - `AegisVault` (in-process wasm-bindgen backend, v0.1+)
 *   - `IframeHostVaultClient` (cross-origin iframe backend, Phase D, future)
 *
 * All cross-boundary methods are async. Consumer code should `await` them
 * regardless of which backend is in use.
 */
export interface VaultClient {
  // ── Observable state (sync — local mirror of the backend state) ───────────
  readonly state: VaultState;
  readonly locked: boolean;
  readonly persistent: boolean;
  subscribe(listener: VaultStateListener): () => void;

  // ── Lifecycle (async — may cross a transport boundary) ────────────────────
  exists(): Promise<boolean>;
  create(passphrase: string, prfOutput?: Uint8Array): Promise<void>;
  unlock(passphrase: string, prfOutput?: Uint8Array): Promise<void>;
  startEphemeral(): Promise<void>;
  /** Lock is synchronous — local zeroize, fire-and-forget in iframe mode. */
  lock(): void;
  delete(): Promise<void>;

  // ── Pages (async — RTT in iframe mode, microtask in process mode) ────────
  pageGet(name: string, key: string): Promise<string | null>;
  pageSet(name: string, key: string, value: string): Promise<void>;
  pageDelete(name: string, key: string): Promise<void>;
  pageEntries(name: string): Promise<Record<string, string>>;

  // ── Identity ──────────────────────────────────────────────────────────────
  identityOpen(purpose: string): Promise<IdentityHandleClient>;
}

/**
 * Opaque handle to a per-purpose Ed25519 identity.
 *
 * `pubkey` is cached at open time (returned as part of the open response in
 * the iframe case) so it's synchronously available — no per-call RTT for
 * reading the public key. `sign` and `close` are async to accommodate the
 * iframe transport.
 */
export interface IdentityHandleClient {
  /** 32-byte Ed25519 public key for this purpose. Cached, always present. */
  readonly pubkey: Uint8Array;

  /**
   * Sign canonical bytes under domain separation.
   *
   * The signature is over `SHA-512(purpose_tag || canonical_bytes)` using
   * Ed25519. Cross-protocol attacks against other purposes' signing oracles
   * are structurally impossible — a signature produced for purpose A does
   * not verify under purpose B's pubkey even with identical canonical bytes.
   */
  sign(canonicalBytes: Uint8Array): Promise<Uint8Array>;

  /** Release the handle. After close, further sign()/pubkey access is undefined. */
  close(): Promise<void>;
}
