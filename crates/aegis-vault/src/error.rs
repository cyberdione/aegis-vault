//! Error types. `VaultError` derives `std::error::Error` via `thiserror`,
//! so wasm-bindgen's blanket `impl<E: StdError> From<E> for JsError` handles
//! the conversion automatically. We deliberately keep the Display strings
//! coarse — anything that could be used as an oracle (wrong passphrase vs
//! corrupt blob vs tampered ciphertext) collapses to the same `"could not
//! unlock vault"` message.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault format error: {0}")]
    Format(&'static str),

    #[error("key derivation failed")]
    Kdf,

    /// AEAD verification failure. String is deliberately the same opaque
    /// "could not unlock vault" message regardless of whether it was a wrong
    /// passphrase, a wrong WebAuthn PRF, or a tampered blob — these MUST be
    /// indistinguishable to callers.
    #[error("could not unlock vault")]
    Aead,

    #[error("{0}")]
    InvalidArgument(&'static str),

    #[error("internal error: {0}")]
    Internal(&'static str),
}
