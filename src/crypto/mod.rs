//! Cryptographic primitives for wallets
//!
//! This module re-exports tari-crypto functionality for use in wallets,
//! avoiding duplication and ensuring compatibility with the main Tari implementation.

// Re-export domain separated hashing from tari-crypto
pub use tari_crypto::hashing::{DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation};

// Re-export Ristretto keys from tari-crypto
pub use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};

// Re-export key traits from tari-crypto
pub use tari_crypto::keys::{PublicKey, SecretKey};

// Re-export signature types from tari-crypto
pub use tari_crypto::signatures::SchnorrSignature;

// Keep our domain definitions but use the tari-crypto traits
pub mod hash_domain;
pub mod signing;

pub use hash_domain::{KeyManagerDomain, WalletMessageSigningDomain};
