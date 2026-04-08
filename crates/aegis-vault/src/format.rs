//! On-disk blob layout for the meta record and per-page records.
//!
//! Both formats are versioned at byte 0 so future migrations can branch on
//! the version byte without breaking earlier readers. The page-blob layout
//! also carries a monotonic counter so a future cross-device sync layer can
//! resolve last-writer-wins without retrofit.
//!
//! Wire formats:
//!
//! ```text
//! META blob (IDB key "meta-v1"):
//!   [0]      version: u8 = 1
//!   [1]      kdf_id:  u8 = 1   // Argon2id
//!   [2..6]   argon2_m: u32 LE  // memory cost (KiB)
//!   [6..8]   argon2_t: u16 LE  // time cost
//!   [8]      argon2_p: u8      // parallelism
//!   [9]      aead_id: u8 = 1   // AES-256-GCM
//!   [10..42] kdf_salt: [u8; 32]
//!   [42..54] root_seed_iv:  [u8; 12]
//!   [54..102] root_seed_ct: [u8; 48]   // 32 plaintext + 16 GCM tag
//!   [102..104] webauthn_blob_len: u16 LE
//!   [104..104+N] webauthn_blob (optional, AES-GCM payload)
//! ```
//!
//! ```text
//! PAGE blob (IDB key "page:<name>"):
//!   [0]      version: u8 = 1
//!   [1]      page_id: u8       // see PageId enum
//!   [2..10]  counter: u64 LE   // monotonic per-page
//!   [10..22] iv: [u8; 12]      // AES-GCM nonce
//!   [22..]   ciphertext + 16-byte tag
//! ```

use crate::error::VaultError;

pub const META_VERSION: u8 = 1;
pub const PAGE_VERSION: u8 = 1;

pub const KDF_ARGON2ID: u8 = 1;
pub const AEAD_AES256GCM: u8 = 1;

/// Argon2id parameters baked into v1 meta blobs.
///
/// Memory cost m=19 MiB, time cost t=2, parallelism p=1.
/// Matches the Onion Shell vault tuning, gives ~500ms-1s on a midrange laptop
/// in browser WASM. Verified that argon2's pure-Rust implementation produces
/// the same Argon2id output as a reference implementation for these params.
pub const ARGON2_M_KIB: u32 = 19 * 1024;
pub const ARGON2_T: u16 = 2;
pub const ARGON2_P: u8 = 1;
pub const KDF_SALT_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

/// Root identity seed length: 32 bytes feeding both Ed25519 and X25519 derivation.
pub const ROOT_SEED_LEN: usize = 32;
/// Encrypted root seed = plaintext + AEAD tag.
pub const ROOT_SEED_CT_LEN: usize = ROOT_SEED_LEN + AEAD_TAG_LEN;

const META_HEADER_LEN: usize = 1 // version
    + 1 // kdf_id
    + 4 // argon2_m
    + 2 // argon2_t
    + 1 // argon2_p
    + 1 // aead_id
    + KDF_SALT_LEN
    + AEAD_NONCE_LEN
    + ROOT_SEED_CT_LEN
    + 2; // webauthn_blob_len

/// Numeric page identifiers. Stored in the page blob's `page_id` byte so the
/// encrypted-blob layer doesn't depend on string page names — sync routing
/// can match by id without consulting the cleartext name.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageId {
    Hosts = 1,
    Auth = 2,
    Llm = 3,
    Prefs = 4,
    /// Reserved for unknown / forward-compat. Decoders that see this should
    /// preserve the bytes verbatim and let a newer version interpret them.
    Reserved = 0xFF,
}

impl PageId {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "hosts" => Some(Self::Hosts),
            "auth" => Some(Self::Auth),
            "llm" => Some(Self::Llm),
            "prefs" => Some(Self::Prefs),
            _ => None,
        }
    }

    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Hosts,
            2 => Self::Auth,
            3 => Self::Llm,
            4 => Self::Prefs,
            _ => Self::Reserved,
        }
    }
}

/// Decoded meta blob header. Owned, no borrows from the input.
#[derive(Debug, Clone)]
pub struct MetaHeader {
    pub version: u8,
    pub kdf_id: u8,
    pub argon2_m: u32,
    pub argon2_t: u16,
    pub argon2_p: u8,
    pub aead_id: u8,
    pub kdf_salt: [u8; KDF_SALT_LEN],
    pub root_seed_iv: [u8; AEAD_NONCE_LEN],
    pub root_seed_ct: [u8; ROOT_SEED_CT_LEN],
    /// Empty if no WebAuthn enrollment present.
    pub webauthn_blob: Vec<u8>,
}

impl MetaHeader {
    pub fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let wa_len: u16 = u16::try_from(self.webauthn_blob.len())
            .map_err(|_| VaultError::Format("webauthn blob exceeds u16::MAX"))?;
        let mut out = Vec::with_capacity(META_HEADER_LEN + self.webauthn_blob.len());
        out.push(self.version);
        out.push(self.kdf_id);
        out.extend_from_slice(&self.argon2_m.to_le_bytes());
        out.extend_from_slice(&self.argon2_t.to_le_bytes());
        out.push(self.argon2_p);
        out.push(self.aead_id);
        out.extend_from_slice(&self.kdf_salt);
        out.extend_from_slice(&self.root_seed_iv);
        out.extend_from_slice(&self.root_seed_ct);
        out.extend_from_slice(&wa_len.to_le_bytes());
        out.extend_from_slice(&self.webauthn_blob);
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, VaultError> {
        if buf.len() < META_HEADER_LEN {
            return Err(VaultError::Format("meta blob truncated"));
        }
        let version = buf[0];
        if version != META_VERSION {
            return Err(VaultError::Format("unsupported meta blob version"));
        }
        let kdf_id = buf[1];
        if kdf_id != KDF_ARGON2ID {
            return Err(VaultError::Format("unsupported KDF"));
        }
        // Direct byte indexing: buf length ≥ META_HEADER_LEN was checked above.
        let argon2_m = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let argon2_t = u16::from_le_bytes([buf[6], buf[7]]);
        let argon2_p = buf[8];
        let aead_id = buf[9];
        if aead_id != AEAD_AES256GCM {
            return Err(VaultError::Format("unsupported AEAD"));
        }
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        kdf_salt.copy_from_slice(&buf[10..10 + KDF_SALT_LEN]);
        let mut root_seed_iv = [0u8; AEAD_NONCE_LEN];
        root_seed_iv.copy_from_slice(&buf[42..42 + AEAD_NONCE_LEN]);
        let mut root_seed_ct = [0u8; ROOT_SEED_CT_LEN];
        root_seed_ct.copy_from_slice(&buf[54..54 + ROOT_SEED_CT_LEN]);

        let wa_len_off = 54 + ROOT_SEED_CT_LEN;
        let wa_len = u16::from_le_bytes([buf[wa_len_off], buf[wa_len_off + 1]]) as usize;
        let wa_start = wa_len_off + 2;
        if buf.len() < wa_start + wa_len {
            return Err(VaultError::Format("meta blob webauthn payload truncated"));
        }
        let webauthn_blob = buf[wa_start..wa_start + wa_len].to_vec();

        Ok(Self {
            version,
            kdf_id,
            argon2_m,
            argon2_t,
            argon2_p,
            aead_id,
            kdf_salt,
            root_seed_iv,
            root_seed_ct,
            webauthn_blob,
        })
    }
}

/// Decoded page blob header (the encrypted body is held alongside).
#[derive(Debug, Clone)]
pub struct PageHeader {
    pub version: u8,
    pub page_id: PageId,
    pub counter: u64,
    pub iv: [u8; AEAD_NONCE_LEN],
}

const PAGE_HEADER_LEN: usize = 1 + 1 + 8 + AEAD_NONCE_LEN;

impl PageHeader {
    pub fn encode_with_body(&self, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAGE_HEADER_LEN + body.len());
        out.push(self.version);
        out.push(self.page_id as u8);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(body);
        out
    }

    /// Returns the parsed header and a slice into the input pointing at the
    /// ciphertext (with trailing AEAD tag). The returned slice borrows `buf`.
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), VaultError> {
        if buf.len() < PAGE_HEADER_LEN {
            return Err(VaultError::Format("page blob truncated"));
        }
        let version = buf[0];
        if version != PAGE_VERSION {
            return Err(VaultError::Format("unsupported page blob version"));
        }
        let page_id = PageId::from_byte(buf[1]);
        let counter = u64::from_le_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        let mut iv = [0u8; AEAD_NONCE_LEN];
        iv.copy_from_slice(&buf[10..10 + AEAD_NONCE_LEN]);
        Ok((
            Self {
                version,
                page_id,
                counter,
                iv,
            },
            &buf[PAGE_HEADER_LEN..],
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::str_to_string)]
mod tests {
    use super::*;

    #[test]
    fn meta_roundtrip_no_webauthn() {
        let h = MetaHeader {
            version: META_VERSION,
            kdf_id: KDF_ARGON2ID,
            argon2_m: ARGON2_M_KIB,
            argon2_t: ARGON2_T,
            argon2_p: ARGON2_P,
            aead_id: AEAD_AES256GCM,
            kdf_salt: [0x42; KDF_SALT_LEN],
            root_seed_iv: [0xAB; AEAD_NONCE_LEN],
            root_seed_ct: [0xCD; ROOT_SEED_CT_LEN],
            webauthn_blob: Vec::new(),
        };
        let encoded = h.encode().unwrap();
        let decoded = MetaHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, META_VERSION);
        assert_eq!(decoded.argon2_m, ARGON2_M_KIB);
        assert_eq!(decoded.kdf_salt, [0x42; KDF_SALT_LEN]);
        assert_eq!(decoded.root_seed_ct, [0xCD; ROOT_SEED_CT_LEN]);
        assert!(decoded.webauthn_blob.is_empty());
    }

    #[test]
    fn meta_roundtrip_with_webauthn() {
        let wa = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let h = MetaHeader {
            version: META_VERSION,
            kdf_id: KDF_ARGON2ID,
            argon2_m: ARGON2_M_KIB,
            argon2_t: ARGON2_T,
            argon2_p: ARGON2_P,
            aead_id: AEAD_AES256GCM,
            kdf_salt: [0x01; KDF_SALT_LEN],
            root_seed_iv: [0x02; AEAD_NONCE_LEN],
            root_seed_ct: [0x03; ROOT_SEED_CT_LEN],
            webauthn_blob: wa.clone(),
        };
        let encoded = h.encode().unwrap();
        let decoded = MetaHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.webauthn_blob, wa);
    }

    #[test]
    fn page_roundtrip() {
        let body = vec![0xAA; 64];
        let h = PageHeader {
            version: PAGE_VERSION,
            page_id: PageId::Auth,
            counter: 42,
            iv: [0x09; AEAD_NONCE_LEN],
        };
        let encoded = h.encode_with_body(&body);
        let (decoded, ct) = PageHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, PAGE_VERSION);
        assert_eq!(decoded.page_id, PageId::Auth);
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.iv, [0x09; AEAD_NONCE_LEN]);
        assert_eq!(ct, &body[..]);
    }

    #[test]
    fn meta_rejects_truncated() {
        let buf = vec![1u8; 8];
        assert!(MetaHeader::decode(&buf).is_err());
    }

    #[test]
    fn page_rejects_truncated() {
        let buf = vec![1u8; 4];
        assert!(PageHeader::decode(&buf).is_err());
    }

    #[test]
    fn page_id_from_name() {
        assert_eq!(PageId::from_name("hosts"), Some(PageId::Hosts));
        assert_eq!(PageId::from_name("auth"), Some(PageId::Auth));
        assert_eq!(PageId::from_name("llm"), Some(PageId::Llm));
        assert_eq!(PageId::from_name("prefs"), Some(PageId::Prefs));
        assert_eq!(PageId::from_name("nonsense"), None);
    }
}
