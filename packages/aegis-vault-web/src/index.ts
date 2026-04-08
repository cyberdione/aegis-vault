/**
 * @cyberdione/aegis-vault-web — encrypted browser identity vault.
 *
 * Vanilla TypeScript core. Runs in any browser context — framework-free.
 * This is the canonical entry point; React / Vue / other framework adapters
 * live in sub-paths (`./react`, future `./vue`, etc.) and are built *on top*
 * of this module, not alongside it.
 *
 * Wraps the wasm-bindgen `Vault` core with IndexedDB persistence, locked /
 * persistent state tracking, BroadcastChannel tab-coherence, and async
 * wrapping per the forward-compatible cross-boundary contract (see
 * README §"Async API contract").
 *
 * The Rust core has no notion of "mode" or persistence. This shim is
 * responsible for:
 *   - reading/writing the meta blob and per-page blobs to IDB
 *   - tracking `locked` and `persistent` boolean state
 *   - notifying other tabs when the vault state changes
 *   - wrapping synchronous wasm methods in async contracts so the iframe
 *     transport (Phase D) can be dropped in later without consumer churn
 *
 * The Rust core is responsible for all crypto and identity derivation.
 *
 * See README.md and THREATMODEL.md at the repo root for design rationale.
 */

import initWasm, {
  Vault as WasmVault,
  IdentityHandle as WasmIdentityHandle,
} from '../pkg/aegis_vault.js';

import type {
  VaultClient,
  VaultState,
  VaultStateListener,
  IdentityHandleClient,
} from './types.js';

export type {
  VaultClient,
  VaultState,
  VaultStateListener,
  IdentityHandleClient,
} from './types.js';

// ────────────────────────────────────────────────────────────────────────────
// IDB layer
// ────────────────────────────────────────────────────────────────────────────

const VAULT_DB = 'aegis-vault';
const VAULT_STORE = 'vault';
const META_KEY = 'meta-v1';
const PAGE_KEY_PREFIX = 'page:';

let _db: IDBDatabase | null = null;

function openDb(): Promise<IDBDatabase> {
  if (_db) return Promise.resolve(_db);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(VAULT_DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE, { keyPath: 'key' });
      }
    };
    req.onsuccess = () => {
      _db = req.result;
      resolve(_db);
    };
    req.onerror = () => reject(new Error('Failed to open vault database'));
  });
}

interface IdbRecord {
  key: string;
  blob: Uint8Array;
}

async function idbGet(key: string): Promise<Uint8Array | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, 'readonly');
    const req = tx.objectStore(VAULT_STORE).get(key);
    req.onsuccess = () => {
      const r = req.result as IdbRecord | undefined;
      resolve(r ? r.blob : null);
    };
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(key: string, blob: Uint8Array): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, 'readwrite');
    tx.objectStore(VAULT_STORE).put({ key, blob });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbClear(): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(VAULT_STORE, 'readwrite');
    tx.objectStore(VAULT_STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ────────────────────────────────────────────────────────────────────────────
// WASM init (idempotent, lazy)
// ────────────────────────────────────────────────────────────────────────────

let _wasmReady: Promise<void> | null = null;

/**
 * Initialize the wasm module. Idempotent — safe to call multiple times.
 * Consumers normally don't call this directly; `AegisVault.exists()` /
 * `unlock` / `create` / `startEphemeral` will trigger init on first use.
 */
export function loadVaultWasm(): Promise<void> {
  if (_wasmReady) return _wasmReady;
  _wasmReady = (async () => {
    await initWasm();
  })();
  return _wasmReady;
}

// ────────────────────────────────────────────────────────────────────────────
// InProcessIdentityHandle — wraps the raw wasm IdentityHandle
// ────────────────────────────────────────────────────────────────────────────

/**
 * In-process implementation of `IdentityHandleClient`.
 *
 * Wraps the raw wasm-bindgen `IdentityHandle` with async method signatures
 * (for forward-compat with the iframe-host transport in Phase D) and caches
 * the 32-byte pubkey at construction so reading it is synchronous.
 */
class InProcessIdentityHandle implements IdentityHandleClient {
  readonly pubkey: Uint8Array;
  private inner: WasmIdentityHandle | null;

  constructor(inner: WasmIdentityHandle) {
    // Snapshot the pubkey synchronously at open time. The underlying wasm
    // handle owns the derived signing key; pubkey is derived deterministically
    // from the purpose + root seed and is stable for the lifetime of the key.
    this.pubkey = inner.pubkey();
    this.inner = inner;
  }

  /**
   * Sign canonical bytes under domain separation. Async per the forward-compat
   * contract; in-process resolution is one microtask.
   */
  async sign(canonicalBytes: Uint8Array): Promise<Uint8Array> {
    if (!this.inner) {
      throw new Error('IdentityHandle is closed');
    }
    return this.inner.sign(canonicalBytes);
  }

  /**
   * Drop the handle, zeroizing the derived key. After close, the handle is
   * no longer usable. Async per the forward-compat contract.
   */
  async close(): Promise<void> {
    if (this.inner) {
      this.inner.close();
      this.inner = null;
    }
  }
}

// ────────────────────────────────────────────────────────────────────────────
// AegisVault — TS-side wrapper holding state + IDB glue
// ────────────────────────────────────────────────────────────────────────────

const TAB_SYNC_CHANNEL = 'aegis-vault';

/**
 * In-process implementation of `VaultClient`. Holds the wasm `Vault`
 * instance, manages IDB persistence, and broadcasts state changes to other
 * tabs via `BroadcastChannel`.
 *
 * Consumers normally use the `vault` singleton exported at the bottom of
 * this module. Apps that need multiple isolated vault instances (rare;
 * multi-vault is a v2 feature) can construct their own `AegisVault`.
 *
 * This class implements `VaultClient`, the transport-agnostic interface
 * that also has a cross-origin iframe backend in Phase D. Consumer code
 * should prefer the interface type for forward compatibility.
 */
export class AegisVault implements VaultClient {
  private inner: WasmVault | null = null;
  private _state: VaultState = { locked: true, persistent: false };
  private listeners = new Set<VaultStateListener>();
  private channel: BroadcastChannel | null = null;

  constructor() {
    if (typeof BroadcastChannel !== 'undefined') {
      this.channel = new BroadcastChannel(TAB_SYNC_CHANNEL);
      this.channel.addEventListener('message', (ev) => {
        // Cross-tab notification: another tab unlocked, locked, or wrote.
        // For v0.2, we emit a generic state change so consumers can refetch
        // their pages. v0.3 will carry page-level deltas.
        if (ev.data?.type === 'invalidate') {
          this.notify();
        }
      });
    }
  }

  // ── State ─────────────────────────────────────────────────────────────────

  get state(): VaultState {
    return this._state;
  }

  get locked(): boolean {
    return this._state.locked;
  }

  get persistent(): boolean {
    return this._state.persistent;
  }

  /** Subscribe to state changes. Returns an unsubscribe function. */
  subscribe(listener: VaultStateListener): () => void {
    this.listeners.add(listener);
    listener(this._state);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private setState(next: VaultState): void {
    this._state = next;
    this.notify();
    this.broadcast();
  }

  private notify(): void {
    for (const l of this.listeners) {
      l(this._state);
    }
  }

  private broadcast(): void {
    this.channel?.postMessage({ type: 'invalidate' });
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /** True if a persistent vault exists in IDB. Triggers wasm init. */
  async exists(): Promise<boolean> {
    await loadVaultWasm();
    const meta = await idbGet(META_KEY);
    return meta !== null;
  }

  /**
   * Create a new persistent vault. Generates a fresh root identity seed,
   * derives the meta key from passphrase + optional WebAuthn PRF, encrypts
   * the seed, and writes the meta blob to IDB.
   */
  async create(passphrase: string, prfOutput?: Uint8Array): Promise<void> {
    await loadVaultWasm();
    if (this.inner) {
      throw new Error('Vault is already unlocked; call lock() first');
    }
    const v = WasmVault.createNew(passphrase, prfOutput ?? null);
    const meta = v.metaBlob();
    await idbPut(META_KEY, meta);
    this.inner = v;
    this.setState({ locked: false, persistent: true });
  }

  /**
   * Unlock an existing persistent vault from its IDB-stored meta blob.
   * Throws if no vault exists, if the passphrase is wrong, or if WebAuthn
   * PRF mismatch. Errors are deliberately ambiguous to prevent oracles.
   */
  async unlock(passphrase: string, prfOutput?: Uint8Array): Promise<void> {
    await loadVaultWasm();
    if (this.inner) {
      throw new Error('Vault is already unlocked; call lock() first');
    }
    const meta = await idbGet(META_KEY);
    if (!meta) {
      throw new Error('No vault exists');
    }
    const v = WasmVault.unlock(meta, passphrase, prfOutput ?? null);
    this.inner = v;
    // Pre-load all well-known pages. Missing pages are skipped silently.
    for (const name of WELL_KNOWN_PAGES) {
      const blob = await idbGet(PAGE_KEY_PREFIX + name);
      if (blob) {
        try {
          v.pageLoad(name, blob);
        } catch (_e) {
          // A corrupted page blob shouldn't block unlocking the rest of the
          // vault. Consumer-installable error hook is a v0.3 concern.
        }
      }
    }
    this.setState({ locked: false, persistent: true });
  }

  /**
   * Start an ephemeral session — fresh in-memory root seed, no IDB writes.
   * The Rust crate generates the seed; the TS shim records `persistent: false`
   * so subsequent `pageSet` writes don't touch IDB.
   *
   * **Deliberately not named `startAnonymous` to avoid the hyprstream
   * `Subject: anonymous` collision.** See README §"Naming: avoiding `anonymous`".
   */
  async startEphemeral(): Promise<void> {
    await loadVaultWasm();
    if (this.inner) {
      throw new Error('Vault is already unlocked; call lock() first');
    }
    this.inner = WasmVault.ephemeral();
    this.setState({ locked: false, persistent: false });
  }

  /**
   * Lock the vault: drop the wasm `Vault` (which zeroizes its secrets),
   * clear in-memory state, and return to the locked state.
   *
   * Synchronous — local zeroize only, no transport boundary crossing.
   * In the future iframe-host backend, lock will be a fire-and-forget
   * postMessage; callers that want to wait for the iframe to confirm
   * can listen for the subsequent `subscribe` callback.
   *
   * Does NOT delete the IDB-persisted vault. Call `delete()` for that.
   */
  lock(): void {
    if (this.inner) {
      this.inner.lock();
      this.inner = null;
    }
    this.setState({ locked: true, persistent: false });
  }

  /**
   * Permanently delete the persistent vault from IDB. The user will need
   * to create a new vault on next unlock. Use `lock()` if you only want to
   * forget the in-memory state.
   */
  async delete(): Promise<void> {
    if (this.inner) {
      this.inner.lock();
      this.inner = null;
    }
    await idbClear();
    this.setState({ locked: true, persistent: false });
  }

  // ── Pages (async per the forward-compat contract) ────────────────────────

  /**
   * Look up a key in a page. Returns `null` for absent keys or unloaded
   * pages. Async per the forward-compat contract; in-process resolution is
   * one microtask.
   */
  async pageGet(name: string, key: string): Promise<string | null> {
    if (!this.inner) return null;
    return this.inner.pageGet(name, key) ?? null;
  }

  /**
   * Return all entries in a page as a plain object. Empty object for absent
   * or unloaded pages. Async per the forward-compat contract.
   */
  async pageEntries(name: string): Promise<Record<string, string>> {
    if (!this.inner) return {};
    return (this.inner.pageEntries(name) as Record<string, string>) ?? {};
  }

  /**
   * Set a key in a page. Encrypts the page state and persists to IDB if the
   * vault is persistent; otherwise just updates in-memory state.
   */
  async pageSet(name: string, key: string, value: string): Promise<void> {
    if (!this.inner) {
      throw new Error('Vault is locked');
    }
    this.inner.pageSet(name, key, value);
    if (this._state.persistent) {
      const blob = this.inner.pageEncrypt(name);
      await idbPut(PAGE_KEY_PREFIX + name, blob);
      this.broadcast();
    }
  }

  async pageDelete(name: string, key: string): Promise<void> {
    if (!this.inner) {
      throw new Error('Vault is locked');
    }
    this.inner.pageDelete(name, key);
    if (this._state.persistent) {
      const blob = this.inner.pageEncrypt(name);
      await idbPut(PAGE_KEY_PREFIX + name, blob);
      this.broadcast();
    }
  }

  // ── Identity ──────────────────────────────────────────────────────────────

  /**
   * Open an identity for a stable purpose label. Returns an opaque
   * `IdentityHandleClient` whose `sign()` and `pubkey` proxy to a derived
   * per-purpose Ed25519 key inside wasm linear memory.
   *
   * The seed never crosses into JS. The handle holds a reference to its
   * own derived signing key (a 32-byte HKDF expansion of the root seed
   * with a purpose-specific info string).
   *
   * Async per the forward-compat contract; in-process resolution is one
   * microtask. In the future iframe-host backend, this call round-trips a
   * postMessage so the iframe can derive + register the handle.
   */
  async identityOpen(purpose: string): Promise<IdentityHandleClient> {
    if (!this.inner) {
      throw new Error('Vault is locked');
    }
    return new InProcessIdentityHandle(this.inner.identityOpen(purpose));
  }
}

/**
 * Pages this vault pre-loads automatically on unlock. Consumers can store
 * data in any page name that the Rust crate recognizes, but only the names
 * listed here are lazy-loaded into memory at unlock time. Pages not in this
 * list must be loaded explicitly by the caller if needed.
 *
 * Page names map to numeric `PageId` values inside the Rust crate; both
 * sides must agree.
 */
export const WELL_KNOWN_PAGES = ['hosts', 'auth', 'llm', 'prefs'] as const;
export type WellKnownPage = (typeof WELL_KNOWN_PAGES)[number];

/**
 * Singleton instance for apps that want one global vault. The default vault
 * used by `@cyberdione/aegis-vault-web/widget` and `@cyberdione/aegis-vault-web/react`.
 *
 * Apps that need multiple isolated vault instances (rare; multi-vault is a
 * v2 feature) can construct their own `AegisVault` directly.
 */
export const vault: VaultClient = new AegisVault();

// Re-export for convenience
export { WELL_KNOWN_PAGES as PAGES };
