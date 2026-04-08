//! Crypto primitives — KDF, AEAD, MAC.
//!
//! All keys are wrapped in `Zeroizing<...>` so they wipe on drop.
//! Functions are deterministic given their inputs and have no internal state.

use crate::error::VaultError;
use crate::format::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, ARGON2_M_KIB, ARGON2_P, ARGON2_T, ROOT_SEED_CT_LEN, ROOT_SEED_LEN,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Run Argon2id over `passphrase` with the given salt, producing 32 bytes.
///
/// Uses parameters from `format::ARGON2_*`. Output is wrapped in
/// `Zeroizing` so it wipes on drop.
pub fn argon2id_derive(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T as u32, ARGON2_P as u32, Some(32))
        .map_err(|_| VaultError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut_slice())
        .map_err(|_| VaultError::Kdf)?;
    Ok(out)
}

/// HKDF-SHA256 expand. `ikm` is the input keying material, `info` is the
/// domain-separation tag. Returns 32 bytes.
pub fn hkdf_expand_32(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    // Salt is fixed all-zeros (HKDF-Extract with no salt) since the IKM is
    // already a uniformly random key from Argon2id or HKDF — there's no
    // attacker-controlled non-uniform input here.
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    // HKDF-SHA256 can only fail `expand` if the requested output exceeds
    // 255 * hash_output_size (255 * 32 = 8160 bytes). We request 32 bytes,
    // so failure is structurally impossible. The explicit expect documents
    // this invariant; a real error here would indicate memory corruption.
    #[allow(clippy::expect_used)]
    hkdf.expand(info, out.as_mut_slice())
        .expect("HKDF expand 32 bytes cannot fail");
    out
}

/// HMAC-SHA256(key, data). Used to combine passphrase-derived bytes with
/// WebAuthn PRF output before HKDF-expanding into the master key.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    // `Hmac::new_from_slice` only returns `Err` if the crate is compiled
    // with a buggy backend that rejects some key lengths. For `Hmac<Sha256>`
    // using the RustCrypto backend, every key length (including zero) is
    // accepted — failure is structurally impossible. A real error here
    // would indicate a dependency swap that broke an invariant the vault
    // relies on.
    #[allow(clippy::expect_used)]
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&tag);
    out
}

/// AES-256-GCM encrypt with a caller-provided IV. Used when the IV is part
/// of an outer header (meta blob) and must be deterministic across the encode
/// step. Caller is responsible for IV uniqueness per (key, message) pair.
pub fn aead_encrypt_with_iv(
    key: &[u8; 32],
    iv: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Aead)
}

pub fn aead_decrypt(
    key: &[u8; 32],
    iv: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::Aead)
}

/// Encrypt the 32-byte root seed for storage in the meta blob. The output
/// is `[u8; 48]` (32 plaintext + 16 GCM tag) and the caller-supplied IV is
/// what gets stored in the meta header at `root_seed_iv`.
pub fn encrypt_root_seed(
    meta_key: &[u8; 32],
    iv: &[u8; AEAD_NONCE_LEN],
    seed: &[u8; ROOT_SEED_LEN],
) -> Result<[u8; ROOT_SEED_CT_LEN], VaultError> {
    let ct = aead_encrypt_with_iv(meta_key, iv, seed, b"aegis-root-seed-v1")?;
    if ct.len() != ROOT_SEED_CT_LEN {
        return Err(VaultError::Internal(
            "unexpected root seed ciphertext length",
        ));
    }
    let mut out = [0u8; ROOT_SEED_CT_LEN];
    out.copy_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_root_seed(
    meta_key: &[u8; 32],
    iv: &[u8; AEAD_NONCE_LEN],
    ct: &[u8; ROOT_SEED_CT_LEN],
) -> Result<Zeroizing<[u8; ROOT_SEED_LEN]>, VaultError> {
    let pt = aead_decrypt(meta_key, iv, ct, b"aegis-root-seed-v1")?;
    if pt.len() != ROOT_SEED_LEN {
        // Should be impossible if the AEAD verified, but defend in depth.
        let mut zeroed = pt;
        zeroed.zeroize();
        return Err(VaultError::Internal(
            "unexpected root seed plaintext length",
        ));
    }
    let mut out = Zeroizing::new([0u8; ROOT_SEED_LEN]);
    out.copy_from_slice(&pt);
    // Drop the heap copy from aead_decrypt eagerly.
    drop(pt);
    Ok(out)
}

// Reference AEAD_TAG_LEN so it's not flagged unused — referenced indirectly
// via ROOT_SEED_CT_LEN which embeds the tag length, but the import remains
// useful as a public re-export point.
#[allow(dead_code)]
const _AEAD_TAG_LEN_REFERENCED: usize = AEAD_TAG_LEN;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::str_to_string)]
mod tests {
    use super::*;

    #[test]
    fn argon2_deterministic_for_same_input() {
        let salt = [0x42; 32];
        let a = argon2id_derive(b"hello", &salt).unwrap();
        let b = argon2id_derive(b"hello", &salt).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn argon2_differs_on_different_passphrase() {
        let salt = [0x42; 32];
        let a = argon2id_derive(b"hello", &salt).unwrap();
        let b = argon2id_derive(b"world", &salt).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn hkdf_expand_differs_per_info() {
        let ikm = [0x55; 32];
        let a = hkdf_expand_32(&ikm, b"info-a");
        let b = hkdf_expand_32(&ikm, b"info-b");
        assert_ne!(*a, *b);
    }

    #[test]
    fn aead_roundtrip() {
        let key = [0x11; 32];
        let iv = [0xAB; AEAD_NONCE_LEN];
        let pt = b"the answer is 42";
        let ct = aead_encrypt_with_iv(&key, &iv, pt, b"aad-ctx").unwrap();
        let recovered = aead_decrypt(&key, &iv, &ct, b"aad-ctx").unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aead_rejects_wrong_aad() {
        let key = [0x11; 32];
        let iv = [0xAB; AEAD_NONCE_LEN];
        let ct = aead_encrypt_with_iv(&key, &iv, b"secret", b"good-aad").unwrap();
        assert!(aead_decrypt(&key, &iv, &ct, b"bad-aad").is_err());
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let key = [0x11; 32];
        let iv = [0xCD; AEAD_NONCE_LEN];
        let mut ct = aead_encrypt_with_iv(&key, &iv, b"secret", b"aad").unwrap();
        ct[0] ^= 0x01;
        assert!(aead_decrypt(&key, &iv, &ct, b"aad").is_err());
    }

    #[test]
    fn root_seed_roundtrip() {
        let meta_key = [0x33; 32];
        let iv = [0x77; AEAD_NONCE_LEN];
        let seed = [0xCC; ROOT_SEED_LEN];
        let ct = encrypt_root_seed(&meta_key, &iv, &seed).unwrap();
        let recovered = decrypt_root_seed(&meta_key, &iv, &ct).unwrap();
        assert_eq!(*recovered, seed);
    }
}
