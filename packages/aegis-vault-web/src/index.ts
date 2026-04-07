/**
 * @cyberdione/aegis-vault-web — encrypted browser identity vault.
 *
 * High-level TypeScript API over the wasm-bindgen `Vault` core.
 * Adds IndexedDB persistence, locked/persistent state tracking, and
 * tab-coherence broadcast.
 *
 * The Rust core has no notion of "mode" or persistence. This shim is
 * responsible for:
 *   - reading/writing the meta blob and per-page blobs to IDB
 *   - tracking `locked` and `persistent` boolean state
 *   - notifying other tabs when the vault state changes
 *
 * The Rust core is responsible for all crypto and identity derivation.
 *
 * See README.md and THREATMODEL.md at the repo root for design rationale.
 */

import initWasm, {
  Vault as WasmVault,
  IdentityHandle,
} from '../pkg/aegis_vault.js';

export { IdentityHandle };
export type { WasmVault };

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
 * `unlock` / `createNew` / `ephemeral` will trigger init on first use.
 */
export function loadVaultWasm(): Promise<void> {
  if (_wasmReady) return _wasmReady;
  _wasmReady = (async () => {
    await initWasm();
  })();
  return _wasmReady;
}

// ────────────────────────────────────────────────────────────────────────────
// AegisVault — TS-side wrapper holding state + IDB glue
// ────────────────────────────────────────────────────────────────────────────

/**
 * State observable by consumers. Two booleans, no enum.
 *
 * - `locked === true`: no in-memory vault. The UI should show an unlock modal.
 * - `locked === false && persistent === true`: vault loaded from (or created
 *   into) IDB. `pageSet` writes survive reload.
 * - `locked === false && persistent === false`: ephemeral in-memory vault.
 *   `pageSet` writes do NOT survive reload. The TS shim silently skips IDB
 *   writes for `pageEncrypt()` output. Consumer code that depends on
 *   persistence should check `persistent` and either skip the operation or
 *   warn the user.
 *
 * **Deliberately not named `anonymous` anywhere.** See README §"Naming:
 * avoiding `anonymous`" — the term collides with hyprstream's `Subject:
 * anonymous`.
 */
export interface VaultState {
  locked: boolean;
  persistent: boolean;
}

const TAB_SYNC_CHANNEL = 'aegis-vault';

type StateListener = (state: VaultState) => void;

/**
 * Top-level vault wrapper. Holds the wasm `Vault` instance, IDB persistence,
 * and tab-sync. Consumers normally use `vault` (the singleton) or wrap this
 * in their own React provider.
 */
export class AegisVault {
  private inner: WasmVault | null = null;
  private _state: VaultState = { locked: true, persistent: false };
  private listeners = new Set<StateListener>();
  private channel: BroadcastChannel | null = null;

  constructor() {
    if (typeof BroadcastChannel !== 'undefined') {
      this.channel = new BroadcastChannel(TAB_SYNC_CHANNEL);
      this.channel.addEventListener('message', (ev) => {
        // Cross-tab notification: another tab unlocked, locked, or wrote.
        // For v0.1, we just emit a generic state change so consumers can
        // refetch their pages. v0.2 will carry deltas.
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
  subscribe(listener: StateListener): () => void {
    this.listeners.add(listener);
    listener(this._state);
    return () => this.listeners.delete(listener);
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
    // Pre-load all pages so subsequent pageGet calls are synchronous.
    // Pages that don't exist in IDB are skipped silently.
    for (const name of WELL_KNOWN_PAGES) {
      const blob = await idbGet(PAGE_KEY_PREFIX + name);
      if (blob) {
        try {
          v.pageLoad(name, blob);
        } catch (_e) {
          // A corrupted page blob shouldn't block unlocking the rest of the
          // vault. Log via a hook the caller can install in v0.2.
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
   * `Subject: anonymous` collision.**
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
   * clear in-memory page state, and re-show the unlock modal. Does NOT
   * delete the IDB-persisted vault — call `delete()` for that.
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

  // ── Pages ─────────────────────────────────────────────────────────────────

  pageGet(name: string, key: string): string | null {
    if (!this.inner) return null;
    return this.inner.pageGet(name, key) ?? null;
  }

  pageEntries(name: string): Record<string, string> {
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
   * `IdentityHandle` whose `sign()` and `pubkey()` methods proxy to the
   * derived per-purpose Ed25519 key inside wasm linear memory.
   *
   * The seed never crosses into JS. The handle holds a reference to its
   * own derived signing key (a 32-byte HKDF expansion of the root seed
   * with a purpose-specific info string).
   */
  identityOpen(purpose: string): IdentityHandle {
    if (!this.inner) {
      throw new Error('Vault is locked');
    }
    return this.inner.identityOpen(purpose);
  }
}

/**
 * Pages this vault knows how to pre-load on unlock. Consumers can store
 * data in any page name they like via `pageSet`, but only the names listed
 * here are lazy-loaded automatically. Cyberdione, Osh, and other consumers
 * may extend this list as new conventions emerge.
 *
 * Page names map to numeric `PageId` values inside the Rust crate; both
 * sides must agree.
 */
export const WELL_KNOWN_PAGES = ['hosts', 'auth', 'llm', 'prefs'] as const;
export type WellKnownPage = (typeof WELL_KNOWN_PAGES)[number];

/**
 * Singleton instance for apps that want one global vault. Apps that need
 * multiple isolated vault instances (rare; multi-vault is a v2 feature) can
 * construct their own `AegisVault` directly.
 */
export const vault = new AegisVault();

// Re-export for convenience
export { WELL_KNOWN_PAGES as PAGES };
