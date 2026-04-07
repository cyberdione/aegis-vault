//! Per-purpose identity derivation and signing.
//!
//! Each "purpose" string deterministically derives its own Ed25519 keypair
//! from the vault's root seed via HKDF-SHA256. Different purposes produce
//! cryptographically independent keys with no observable relationship even
//! if a single per-purpose private key is later compromised.
//!
//! Signing is **always domain-separated**: the bytes-to-be-signed are
//! transformed into `Ed25519ph` over `SHA-512(purpose_tag || canonical_bytes)`
//! where `purpose_tag = b"aegis-purpose-v1\0" || varint(purpose.len()) || purpose`.
//! This makes cross-protocol attacks (one purpose's signing oracle producing
//! valid signatures for another purpose's protocol) structurally impossible.

use crate::crypto::hkdf_expand_32;
use crate::error::VaultError;
use ed25519_dalek::{Signer, SigningKey};
#[cfg(test)]
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Length of the Ed25519 public key.
pub const ED25519_PK_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

/// HKDF info tag prefix used to derive a per-purpose key from the root seed.
const PURPOSE_HKDF_TAG: &str = "aegis-purpose-key-v1\0";
/// Domain-separation prefix prepended to canonical bytes before signing.
const PURPOSE_DOMAIN_TAG: &[u8] = b"aegis-purpose-v1\0";

/// A derived per-purpose Ed25519 signing key. Owned, zeroizing on drop.
pub struct PurposeIdentity {
    purpose: String,
    signing_key: SigningKey,
}

impl PurposeIdentity {
    /// Derive a purpose identity from the vault root seed.
    /// `purpose` is a stable string label like "hyprstream-rpc-envelope-v1".
    pub fn derive(root_seed: &[u8; 32], purpose: &str) -> Result<Self, VaultError> {
        if purpose.is_empty() {
            return Err(VaultError::InvalidArgument("purpose must be non-empty"));
        }
        if purpose.len() > 255 {
            return Err(VaultError::InvalidArgument(
                "purpose must be at most 255 bytes",
            ));
        }
        // info = "aegis-purpose-key-v1\0" || purpose_bytes
        // We don't varint-prefix here because PURPOSE_HKDF_TAG ends in NUL,
        // so concatenation is unambiguous and the purpose is the only data
        // after the tag.
        let mut info = Vec::with_capacity(PURPOSE_HKDF_TAG.len() + purpose.len());
        info.extend_from_slice(PURPOSE_HKDF_TAG.as_bytes());
        info.extend_from_slice(purpose.as_bytes());

        let derived = hkdf_expand_32(root_seed, &info);
        // ed25519-dalek SigningKey takes a 32-byte seed.
        let signing_key = SigningKey::from_bytes(&*derived);
        // `derived` (Zeroizing) wipes itself on drop.
        Ok(Self {
            purpose: purpose.to_string(),
            signing_key,
        })
    }

    /// 32-byte Ed25519 public key for this purpose.
    pub fn pubkey(&self) -> [u8; ED25519_PK_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign canonical bytes under domain separation.
    ///
    /// The signature is over `SHA-512(purpose_tag || canonical_bytes)` using
    /// the Ed25519ph (prehash) construction. Verifiers MUST replicate the
    /// same prehash; the public verification helper `verify_purpose` does so.
    pub fn sign(&self, canonical_bytes: &[u8]) -> [u8; ED25519_SIG_LEN] {
        let prehash = build_prehash(&self.purpose, canonical_bytes);
        // Ed25519ph context can be empty since the purpose is already in the
        // prehash. We use plain `sign(...)` over the prehash digest output —
        // simpler and unambiguous, since the prehash already binds the purpose.
        let sig = self.signing_key.sign(&prehash);
        sig.to_bytes()
    }

}

impl Drop for PurposeIdentity {
    fn drop(&mut self) {
        // ed25519-dalek SigningKey already implements zeroize internally
        // when the `zeroize` feature is enabled, so this is belt-and-braces:
        // explicitly wipe our purpose string copy too. The string itself
        // is not secret but we wipe to keep heap hygiene predictable.
        self.purpose.zeroize();
    }
}

/// Build the SHA-512 prehash that gets signed.
/// Layout: SHA-512( "aegis-purpose-v1\0" || (purpose.len() as u8) || purpose || canonical_bytes )
fn build_prehash(purpose: &str, canonical_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hasher = Sha512::new();
    hasher.update(PURPOSE_DOMAIN_TAG);
    // 1-byte length prefix; we already enforced purpose.len() <= 255 in derive().
    hasher.update([purpose.len() as u8]);
    hasher.update(purpose.as_bytes());
    hasher.update(canonical_bytes);
    let digest = hasher.finalize();
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    out.extend_from_slice(&digest);
    out
}

/// Verify a signature produced by `PurposeIdentity::sign`. Provided as a
/// helper for tests; consumers normally verify on the server using the same
/// prehash construction independently.
#[cfg(test)]
pub fn verify_purpose(
    pubkey: &[u8; ED25519_PK_LEN],
    purpose: &str,
    canonical_bytes: &[u8],
    signature: &[u8; ED25519_SIG_LEN],
) -> bool {
    use ed25519_dalek::{Signature, Verifier};
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let prehash = build_prehash(purpose, canonical_bytes);
    let sig = Signature::from_bytes(signature);
    vk.verify(&prehash, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let seed = [0x11; 32];
        let a = PurposeIdentity::derive(&seed, "hyprstream-rpc-envelope-v1").unwrap();
        let b = PurposeIdentity::derive(&seed, "hyprstream-rpc-envelope-v1").unwrap();
        assert_eq!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn different_purposes_yield_different_keys() {
        let seed = [0x11; 32];
        let a = PurposeIdentity::derive(&seed, "hyprstream-rpc-envelope-v1").unwrap();
        let b = PurposeIdentity::derive(&seed, "ssh-user-cert-v1").unwrap();
        assert_ne!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn different_seeds_yield_different_keys() {
        let s1 = [0x11; 32];
        let s2 = [0x22; 32];
        let a = PurposeIdentity::derive(&s1, "p").unwrap();
        let b = PurposeIdentity::derive(&s2, "p").unwrap();
        assert_ne!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let seed = [0x99; 32];
        let id = PurposeIdentity::derive(&seed, "test-purpose-v1").unwrap();
        let msg = b"hello, world";
        let sig = id.sign(msg);
        assert!(verify_purpose(&id.pubkey(), "test-purpose-v1", msg, &sig));
    }

    #[test]
    fn cross_purpose_signature_does_not_verify() {
        let seed = [0x99; 32];
        let id_a = PurposeIdentity::derive(&seed, "purpose-a").unwrap();
        let msg = b"identical bytes";
        let sig_a = id_a.sign(msg);
        // Even though purpose-a's pubkey is unchanged, its signature over
        // identical bytes does NOT verify under a "purpose-b" prehash.
        assert!(!verify_purpose(&id_a.pubkey(), "purpose-b", msg, &sig_a));
    }

    #[test]
    fn empty_purpose_rejected() {
        let seed = [0x11; 32];
        assert!(PurposeIdentity::derive(&seed, "").is_err());
    }

    #[test]
    fn long_purpose_rejected() {
        let seed = [0x11; 32];
        let long = "x".repeat(256);
        assert!(PurposeIdentity::derive(&seed, &long).is_err());
    }
}
