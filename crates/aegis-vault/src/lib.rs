//! aegis-vault — encrypted browser identity vault.
//!
//! Browser-side secret store with passphrase + optional WebAuthn-PRF unlock,
//! AES-256-GCM at rest, HKDF-derived per-page subkeys, and an HSM-shaped
//! per-purpose Ed25519 signing surface. The root identity seed never leaves
//! the vault as raw bytes — consumers obtain `IdentityHandle`s and ask the
//! vault to sign on their behalf.
//!
//! See README.md and THREATMODEL.md at the repo root for design rationale.

#![deny(unsafe_code)]

mod crypto;
mod error;
mod format;
mod identity;
mod page;

use crate::crypto::{
    argon2id_derive, decrypt_root_seed, encrypt_root_seed, hkdf_expand_32, hmac_sha256,
};
use crate::error::VaultError;
use crate::format::{
    MetaHeader, AEAD_AES256GCM, AEAD_NONCE_LEN, ARGON2_M_KIB, ARGON2_P, ARGON2_T, KDF_ARGON2ID,
    KDF_SALT_LEN, META_VERSION, ROOT_SEED_LEN,
};
use crate::identity::PurposeIdentity;
use crate::page::{decrypt_page, encrypt_page, PageState};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// ────────────────────────────────────────────────────────────────────────────
// Vault
// ────────────────────────────────────────────────────────────────────────────

/// The encrypted vault. Holds the unlocked root seed in WASM linear memory
/// and provides accessors for pages and identity slots.
///
/// **The Rust crate has no notion of "mode."** A `Vault` is just an object
/// that exists once unlocked. Whether its page output is persisted to IDB
/// is a TS-shim concern; this crate produces blobs that the shim can either
/// store or discard.
///
/// **The vault never exposes raw seed bytes to JS.** All operations on the
/// identity go through `IdentityHandle::sign(...)`. There is intentionally
/// no `seed()`, `export_seed()`, or `raw_bytes()` accessor.
#[wasm_bindgen]
pub struct Vault {
    root_seed: Zeroizing<[u8; ROOT_SEED_LEN]>,
    /// Cached meta blob for callers that need to re-persist after no-op
    /// changes (e.g. after a slot is opened — slots don't actually mutate
    /// the meta blob, but consumers may want it returned anyway).
    meta_blob: Vec<u8>,
    /// Decrypted in-memory page state, indexed by page name.
    pages: BTreeMap<String, PageState>,
}

#[wasm_bindgen]
impl Vault {
    // ── Lifecycle ────────────────────────────────────────────────────────────

    /// Create a new vault from a passphrase plus optional WebAuthn PRF output.
    ///
    /// Generates a fresh 32-byte root identity seed via the platform RNG,
    /// runs Argon2id over the passphrase, derives a meta key, and encrypts
    /// the root seed under the meta key into the meta blob. The returned
    /// vault is ready to use.
    ///
    /// `prf_output` is the 32 bytes from a WebAuthn PRF assertion if the
    /// caller chose to enroll a hardware second factor. Pass `None` for
    /// passphrase-only.
    #[wasm_bindgen(js_name = createNew)]
    pub fn create_new(
        passphrase: &str,
        prf_output: Option<Vec<u8>>,
    ) -> Result<Vault, JsError> {
        Self::create_new_impl(passphrase, prf_output.as_deref()).map_err(JsError::from)
    }

    /// Internal create — returns the rich error type so unit tests on native
    /// targets don't trigger wasm-bindgen's `JsError::new` panic path.
    pub(crate) fn create_new_impl(
        passphrase: &str,
        prf_output: Option<&[u8]>,
    ) -> Result<Vault, VaultError> {
        if passphrase.is_empty() {
            return Err(VaultError::InvalidArgument("passphrase must be non-empty"));
        }
        let mut salt = [0u8; KDF_SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|_| VaultError::Internal("getrandom"))?;

        // Generate the root seed.
        let mut root_seed = Zeroizing::new([0u8; ROOT_SEED_LEN]);
        getrandom::getrandom(root_seed.as_mut_slice())
            .map_err(|_| VaultError::Internal("getrandom"))?;

        let meta_key = derive_meta_key(passphrase.as_bytes(), &salt, prf_output)?;

        // Encrypt the root seed for storage.
        let mut root_seed_iv = [0u8; AEAD_NONCE_LEN];
        getrandom::getrandom(&mut root_seed_iv)
            .map_err(|_| VaultError::Internal("getrandom"))?;
        let root_seed_ct = encrypt_root_seed(&*meta_key, &root_seed_iv, &*root_seed)?;

        // Build the meta blob. WebAuthn cred storage is currently TS-side
        // (passed into create on each unlock), so meta_webauthn_blob is empty
        // unless a future v0.2 stores credential metadata for autofill.
        let header = MetaHeader {
            version: META_VERSION,
            kdf_id: KDF_ARGON2ID,
            argon2_m: ARGON2_M_KIB,
            argon2_t: ARGON2_T,
            argon2_p: ARGON2_P,
            aead_id: AEAD_AES256GCM,
            kdf_salt: salt,
            root_seed_iv,
            root_seed_ct,
            webauthn_blob: Vec::new(),
        };
        let meta_blob = header.encode();

        Ok(Vault {
            root_seed,
            meta_blob,
            pages: BTreeMap::new(),
        })
    }

    /// Unlock an existing vault from its meta blob (read from IDB by caller).
    #[wasm_bindgen]
    pub fn unlock(
        meta_blob: &[u8],
        passphrase: &str,
        prf_output: Option<Vec<u8>>,
    ) -> Result<Vault, JsError> {
        Self::unlock_impl(meta_blob, passphrase, prf_output.as_deref()).map_err(JsError::from)
    }

    /// Internal unlock — returns the rich error type for native unit tests.
    pub(crate) fn unlock_impl(
        meta_blob: &[u8],
        passphrase: &str,
        prf_output: Option<&[u8]>,
    ) -> Result<Vault, VaultError> {
        let header = MetaHeader::decode(meta_blob)?;
        let meta_key = derive_meta_key(passphrase.as_bytes(), &header.kdf_salt, prf_output)?;
        let root_seed =
            decrypt_root_seed(&*meta_key, &header.root_seed_iv, &header.root_seed_ct)?;
        Ok(Vault {
            root_seed,
            meta_blob: meta_blob.to_vec(),
            pages: BTreeMap::new(),
        })
    }

    /// Create an in-memory ephemeral vault. No IDB persistence — the TS shim
    /// is expected to track this state and skip writing `pageEncrypt()` output
    /// to disk. The Rust crate itself does not distinguish ephemeral from
    /// persistent vaults; this is just a convenience constructor that
    /// generates a fresh root seed without any KDF round.
    ///
    /// **Deliberately not named `anonymous` to avoid confusion with hyprstream's
    /// `Subject: anonymous` concept.** See README §"Naming: avoiding `anonymous`".
    #[wasm_bindgen]
    pub fn ephemeral() -> Result<Vault, JsError> {
        let mut root_seed = Zeroizing::new([0u8; ROOT_SEED_LEN]);
        getrandom::getrandom(root_seed.as_mut_slice())
            .map_err(|_| VaultError::Internal("getrandom"))?;
        Ok(Vault {
            root_seed,
            meta_blob: Vec::new(),
            pages: BTreeMap::new(),
        })
    }

    /// Self-describing meta blob suitable for persisting to IDB. Returns an
    /// empty Vec for ephemeral vaults (those have no meta blob).
    #[wasm_bindgen(js_name = metaBlob)]
    pub fn meta_blob(&self) -> Vec<u8> {
        self.meta_blob.clone()
    }

    /// Explicit lock: drop the vault, zeroizing all in-memory secrets.
    /// After this call the JS-side handle is invalid; any subsequent method
    /// call will throw because wasm-bindgen drops the inner struct.
    #[wasm_bindgen]
    pub fn lock(self) {
        // Drop runs Zeroizing on root_seed and clears pages. Nothing else
        // to do — `self` is consumed by value.
    }

    // ── Pages ───────────────────────────────────────────────────────────────

    /// Decrypt a page from its IDB blob and load it into memory.
    /// Subsequent `pageGet`/`pageSet` calls operate on the loaded state.
    #[wasm_bindgen(js_name = pageLoad)]
    pub fn page_load(&mut self, name: &str, ciphertext: &[u8]) -> Result<(), JsError> {
        let state = decrypt_page(name, ciphertext, &*self.root_seed)?;
        self.pages.insert(name.to_string(), state);
        Ok(())
    }

    /// Look up a key in a page. Returns `null` for absent keys or unloaded
    /// pages. (To distinguish "page not loaded" from "key not in page", call
    /// `pageEntries(name)` first.)
    #[wasm_bindgen(js_name = pageGet)]
    pub fn page_get(&self, name: &str, key: &str) -> Option<String> {
        self.pages.get(name).and_then(|p| p.get(key).cloned())
    }

    /// Set a key in a page. Auto-creates the in-memory page if it doesn't
    /// exist yet. The change is *not* persisted until the caller invokes
    /// `pageEncrypt(name)` and writes the resulting blob to IDB themselves.
    #[wasm_bindgen(js_name = pageSet)]
    pub fn page_set(&mut self, name: &str, key: &str, value: &str) {
        self.pages.entry(name.to_string()).or_default().set(key, value);
    }

    /// Delete a key from a page. No-op if the page or key doesn't exist.
    #[wasm_bindgen(js_name = pageDelete)]
    pub fn page_delete(&mut self, name: &str, key: &str) {
        if let Some(p) = self.pages.get_mut(name) {
            p.delete(key);
        }
    }

    /// Return all entries in a page as a JS object `{ key: value, ... }`.
    /// Empty object for absent / unloaded pages.
    #[wasm_bindgen(js_name = pageEntries)]
    pub fn page_entries(&self, name: &str) -> Result<JsValue, JsError> {
        let map: BTreeMap<&String, &String> = self
            .pages
            .get(name)
            .map(|p| p.entries.iter().collect())
            .unwrap_or_default();
        serde_wasm_bindgen::to_value(&map)
            .map_err(|_| VaultError::Internal("page entries serialize").into())
    }

    /// Encrypt the in-memory page state for IDB write. Increments the page's
    /// monotonic counter. Returns the full versioned blob.
    #[wasm_bindgen(js_name = pageEncrypt)]
    pub fn page_encrypt(&mut self, name: &str) -> Result<Vec<u8>, JsError> {
        let state = self.pages.entry(name.to_string()).or_default();
        let blob = encrypt_page(name, state, &*self.root_seed)?;
        Ok(blob)
    }

    // ── Identity slots ──────────────────────────────────────────────────────

    /// Open (or derive on first call) an identity for a stable purpose label.
    /// Different purposes derive cryptographically independent keypairs.
    /// Returns an opaque handle. The seed is never returned.
    #[wasm_bindgen(js_name = identityOpen)]
    pub fn identity_open(&self, purpose: &str) -> Result<IdentityHandle, JsError> {
        let id = PurposeIdentity::derive(&*self.root_seed, purpose)?;
        Ok(IdentityHandle { inner: id })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// IdentityHandle
// ────────────────────────────────────────────────────────────────────────────

/// Opaque handle to a per-purpose Ed25519 identity.
///
/// The handle owns its own derived signing key (zeroized on drop). It does
/// **not** hold a reference to the parent `Vault`, so JS can keep a handle
/// alive across multiple sign operations without re-deriving each time.
/// Locking the parent vault does not invalidate outstanding handles —
/// callers should drop their handles explicitly when finished.
#[wasm_bindgen]
pub struct IdentityHandle {
    inner: PurposeIdentity,
}

#[wasm_bindgen]
impl IdentityHandle {
    /// 32-byte Ed25519 public key for this purpose.
    /// Stable across vault unlock cycles for the same passphrase + purpose.
    #[wasm_bindgen]
    pub fn pubkey(&self) -> Vec<u8> {
        self.inner.pubkey().to_vec()
    }

    /// Sign canonical bytes under domain separation.
    ///
    /// The signature is over `Sha512(purpose_tag || canonical_bytes)`. A
    /// signature produced for purpose A will NOT verify against purpose B's
    /// pubkey, even for identical canonical bytes. Verifiers must replicate
    /// the same prehash; see README §"Signature verification".
    #[wasm_bindgen]
    pub fn sign(&self, canonical_bytes: &[u8]) -> Vec<u8> {
        self.inner.sign(canonical_bytes).to_vec()
    }

    /// Drop the handle, zeroizing the derived key. Equivalent to letting
    /// JS garbage-collect it, but explicit close gives the caller control
    /// over wipe timing.
    #[wasm_bindgen]
    pub fn close(self) {}
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Derive the meta key from passphrase + salt + optional WebAuthn PRF output.
///
/// Two paths:
/// - **Passphrase only:** `meta_key = HKDF(Argon2id(passphrase, salt), "aegis-meta-v1")`
/// - **With WebAuthn PRF:** `meta_key = HKDF(HMAC(Argon2id(passphrase, salt), HKDF(prf_output, "aegis-webauthn-v1")), "aegis-meta-v1")`
///
/// The HMAC combine ensures *both* the passphrase AND the hardware token
/// are required — losing either makes the vault unrecoverable.
fn derive_meta_key(
    passphrase: &[u8],
    salt: &[u8],
    prf_output: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let passphrase_raw = argon2id_derive(passphrase, salt)?;

    let combined: Zeroizing<[u8; 32]> = if let Some(prf) = prf_output {
        if prf.len() < 16 {
            return Err(VaultError::InvalidArgument("PRF output too short"));
        }
        let webauthn_raw = hkdf_expand_32(prf, b"aegis-webauthn-v1");
        hmac_sha256(&*webauthn_raw, &*passphrase_raw)
    } else {
        let mut c = Zeroizing::new([0u8; 32]);
        c.copy_from_slice(&*passphrase_raw);
        c
    };

    Ok(hkdf_expand_32(&*combined, b"aegis-meta-v1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unlock_roundtrip() {
        let v1 = Vault::create_new("correct horse battery staple", None).unwrap();
        let meta = v1.meta_blob();
        // Simulate JS storing meta and a service later asking for the
        // hyprstream identity pubkey.
        let id1 = v1.identity_open("hyprstream-rpc-envelope-v1").unwrap();
        let pk1 = id1.pubkey();
        drop(v1);

        let v2 = Vault::unlock(&meta, "correct horse battery staple", None).unwrap();
        let id2 = v2.identity_open("hyprstream-rpc-envelope-v1").unwrap();
        let pk2 = id2.pubkey();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails() {
        let v1 = Vault::create_new_impl("right", None).unwrap();
        let meta = v1.meta_blob();
        assert!(Vault::unlock_impl(&meta, "wrong", None).is_err());
    }

    #[test]
    fn ephemeral_each_call_produces_different_identity() {
        let v1 = Vault::ephemeral().unwrap();
        let v2 = Vault::ephemeral().unwrap();
        let pk1 = v1
            .identity_open("test-v1")
            .unwrap()
            .pubkey();
        let pk2 = v2
            .identity_open("test-v1")
            .unwrap()
            .pubkey();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn ephemeral_meta_blob_is_empty() {
        let v = Vault::ephemeral().unwrap();
        assert!(v.meta_blob().is_empty());
    }

    #[test]
    fn pages_roundtrip_within_session() {
        let mut v = Vault::create_new("pw", None).unwrap();
        v.page_set("auth", "refresh_token", "abc123");
        v.page_set("auth", "client_id", "client-xyz");
        let blob = v.page_encrypt("auth").unwrap();

        let mut v2 = Vault::unlock(&v.meta_blob(), "pw", None).unwrap();
        v2.page_load("auth", &blob).unwrap();
        assert_eq!(
            v2.page_get("auth", "refresh_token"),
            Some("abc123".to_string())
        );
        assert_eq!(
            v2.page_get("auth", "client_id"),
            Some("client-xyz".to_string())
        );
    }

    #[test]
    fn webauthn_prf_changes_unlock_requirement() {
        let prf_a = vec![0xAA; 32];
        let prf_b = vec![0xBB; 32];
        let v1 = Vault::create_new_impl("pw", Some(&prf_a)).unwrap();
        let meta = v1.meta_blob();
        // Same passphrase, different PRF — fails.
        assert!(Vault::unlock_impl(&meta, "pw", Some(&prf_b)).is_err());
        // No PRF at all — fails.
        assert!(Vault::unlock_impl(&meta, "pw", None).is_err());
        // Same PRF — succeeds.
        assert!(Vault::unlock_impl(&meta, "pw", Some(&prf_a)).is_ok());
    }

    #[test]
    fn purpose_isolation_holds_across_vault_unlock() {
        let v1 = Vault::create_new("pw", None).unwrap();
        let meta = v1.meta_blob();
        let pk_a_v1 = v1.identity_open("purpose-a").unwrap().pubkey();
        let pk_b_v1 = v1.identity_open("purpose-b").unwrap().pubkey();
        drop(v1);

        let v2 = Vault::unlock(&meta, "pw", None).unwrap();
        let pk_a_v2 = v2.identity_open("purpose-a").unwrap().pubkey();
        let pk_b_v2 = v2.identity_open("purpose-b").unwrap().pubkey();

        assert_eq!(pk_a_v1, pk_a_v2);
        assert_eq!(pk_b_v1, pk_b_v2);
        assert_ne!(pk_a_v1, pk_b_v1);
    }
}

