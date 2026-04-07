//! VaultPage — encrypted-at-rest key/value namespace within the vault.
//!
//! Each page has its own AES-256-GCM subkey derived from the root seed via
//! HKDF with a per-page info string. Page contents are JSON-encoded then
//! AEAD-sealed; the resulting ciphertext is stored verbatim in IDB by the
//! TS shim. The vault crate has no IDB knowledge — it only produces and
//! consumes opaque blobs.
//!
//! Page values are strings in v0.1. Binary values can be base64-encoded by
//! the consumer; a future v0.2 may add `pageGetBytes` / `pageSetBytes`
//! variants if a use case appears.

use crate::crypto::{aead_decrypt, aead_encrypt_with_iv, hkdf_expand_32};
use crate::error::VaultError;
use crate::format::{PageHeader, PageId, AEAD_NONCE_LEN, PAGE_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// In-memory page state. BTreeMap for deterministic JSON encoding (so two
/// vaults with the same content produce identical ciphertext modulo IV).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PageState {
    /// Monotonic counter for sync vector. Bumped on every encrypt.
    #[serde(default)]
    pub counter: u64,
    pub entries: BTreeMap<String, String>,
}

impl PageState {
    pub fn get(&self, key: &str) -> Option<&String> {
        self.entries.get(key)
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.entries.insert(key.to_string(), value.to_string());
    }

    pub fn delete(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

/// Derive the AES-GCM subkey for a named page.
/// info = "aegis-page-key-v1\0" || page_name
pub fn derive_page_key(root_seed: &[u8; 32], page_name: &str) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(20 + page_name.len());
    info.extend_from_slice(b"aegis-page-key-v1\0");
    info.extend_from_slice(page_name.as_bytes());
    hkdf_expand_32(root_seed, &info)
}

/// Encrypt a page state for IDB persistence. Bumps the counter, generates a
/// fresh IV, and returns the full versioned blob ready to write.
pub fn encrypt_page(
    page_name: &str,
    state: &mut PageState,
    root_seed: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    let page_id = PageId::from_name(page_name)
        .ok_or(VaultError::InvalidArgument("unknown page name"))?;
    state.counter = state.counter.saturating_add(1);

    // Serialize. We bound length implicitly by IDB blob size; no explicit cap
    // here. A future quota check could live in the TS shim.
    let plaintext = serde_json::to_vec(state)
        .map_err(|_| VaultError::Internal("page json serialize failed"))?;

    let key = derive_page_key(root_seed, page_name);
    let mut iv = [0u8; AEAD_NONCE_LEN];
    getrandom::getrandom(&mut iv).map_err(|_| VaultError::Internal("getrandom failed"))?;

    // AAD binds the encryption to (version, page_id, counter) so a tampered
    // header can't successfully decrypt with a tampered counter pasted in.
    let aad = build_page_aad(PAGE_VERSION, page_id, state.counter);
    let ct = aead_encrypt_with_iv(&*key, &iv, &plaintext, &aad)?;

    let header = PageHeader {
        version: PAGE_VERSION,
        page_id,
        counter: state.counter,
        iv,
    };
    Ok(header.encode_with_body(&ct))
}

/// Decrypt a page blob into its in-memory state.
pub fn decrypt_page(
    page_name: &str,
    blob: &[u8],
    root_seed: &[u8; 32],
) -> Result<PageState, VaultError> {
    let (header, ct) = PageHeader::decode(blob)?;
    let expected_id = PageId::from_name(page_name)
        .ok_or(VaultError::InvalidArgument("unknown page name"))?;
    if header.page_id != expected_id {
        return Err(VaultError::Format("page id mismatch"));
    }
    let key = derive_page_key(root_seed, page_name);
    let aad = build_page_aad(header.version, header.page_id, header.counter);
    let plaintext = aead_decrypt(&*key, &header.iv, ct, &aad)?;
    let state: PageState = serde_json::from_slice(&plaintext)
        .map_err(|_| VaultError::Format("page json malformed"))?;
    Ok(state)
}

fn build_page_aad(version: u8, page_id: PageId, counter: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(2 + 8 + 16);
    aad.extend_from_slice(b"aegis-page-v1\0");
    aad.push(version);
    aad.push(page_id as u8);
    aad.extend_from_slice(&counter.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_roundtrip() {
        let root = [0x44; 32];
        let mut state = PageState::default();
        state.set("key1", "value1");
        state.set("key2", "value2");

        let blob = encrypt_page("auth", &mut state, &root).unwrap();
        assert_eq!(state.counter, 1);

        let decoded = decrypt_page("auth", &blob, &root).unwrap();
        assert_eq!(decoded.counter, 1);
        assert_eq!(decoded.get("key1"), Some(&"value1".to_string()));
        assert_eq!(decoded.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn counter_increments_per_encrypt() {
        let root = [0x55; 32];
        let mut state = PageState::default();
        state.set("k", "v");
        encrypt_page("hosts", &mut state, &root).unwrap();
        encrypt_page("hosts", &mut state, &root).unwrap();
        encrypt_page("hosts", &mut state, &root).unwrap();
        assert_eq!(state.counter, 3);
    }

    #[test]
    fn wrong_page_name_rejected_on_decrypt() {
        let root = [0x66; 32];
        let mut state = PageState::default();
        state.set("k", "v");
        let blob = encrypt_page("auth", &mut state, &root).unwrap();
        // Decoding as "hosts" must fail because the page id mismatches.
        assert!(decrypt_page("hosts", &blob, &root).is_err());
    }

    #[test]
    fn unknown_page_name_rejected() {
        let root = [0x77; 32];
        let mut state = PageState::default();
        assert!(encrypt_page("totally-unknown", &mut state, &root).is_err());
    }

    #[test]
    fn tampered_blob_fails_decrypt() {
        let root = [0x88; 32];
        let mut state = PageState::default();
        state.set("k", "v");
        let mut blob = encrypt_page("prefs", &mut state, &root).unwrap();
        // Flip a byte in the ciphertext region (after the 22-byte header).
        let n = blob.len();
        blob[n - 1] ^= 0x01;
        assert!(decrypt_page("prefs", &blob, &root).is_err());
    }

    #[test]
    fn wrong_root_fails_decrypt() {
        let mut state = PageState::default();
        state.set("k", "v");
        let blob = encrypt_page("llm", &mut state, &[0xAA; 32]).unwrap();
        assert!(decrypt_page("llm", &blob, &[0xBB; 32]).is_err());
    }
}
