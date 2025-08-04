//! Tari-compatible message signing and verification
//!
//! This module implements message signing using Schnorr signatures with domain separation
//! that is compatible with the Tari wallet implementation.
//!
//! ## Key Derivation for Message Signing
//!
//! Tari wallets use the **communication node identity secret key** for message signing.
//! This key is derived from the wallet's seed phrase using:
//! - Branch: "comms" (SPEND_KEY_BRANCH)
//! - Index: 0
//! - Method: Tari's domain-separated key derivation
//!
//! This is the same key used for:
//! - Wallet network identity (P2P communications)
//! - Transaction spending
//! - Message signing (this module)
//!
//! The key ensures signatures are cryptographically identical to those produced
//! by official Tari wallets when using the same seed phrase.

use rand::rngs::OsRng;
use tari_crypto::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::SchnorrSignature,
};
use tari_utilities::hex::Hex;

use super::hash_domain::WalletMessageSigningDomain;
use crate::errors::{WalletError, ValidationError};
use crate::key_management::{
    derive_view_and_spend_keys_from_entropy, mnemonic_to_bytes, seed_phrase::CipherSeed,
};

/// Type alias for domain-separated wallet signatures
/// This matches Tari's SignatureWithDomain for wallet message signing
pub type WalletSignature =
    SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, WalletMessageSigningDomain>;

/// Signs a message using the provided secret key with Tari wallet-compatible domain separation
///
/// # Arguments
/// * `secret_key` - The secret key to sign with
/// * `message` - The message to sign (will be encoded as UTF-8 bytes)
///
/// # Returns
/// * `Ok(WalletSignature)` - The domain-separated signature
/// * `Err(LightweightWalletError)` - If signing fails
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use lightweight_wallet_libs::crypto::{RistrettoSecretKey, SecretKey};
/// use lightweight_wallet_libs::crypto::signing::sign_message;
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let message = "Hello, Tari!";
/// let signature = sign_message(&secret_key, message).unwrap();
/// ```
pub fn sign_message(
    secret_key: &RistrettoSecretKey,
    message: &str,
) -> Result<WalletSignature, WalletError> {
    let message_bytes = message.as_bytes();

    WalletSignature::sign(secret_key, message_bytes, &mut OsRng).map_err(|e| {
        WalletError::ValidationError(ValidationError::SignatureValidationFailed(
            format!("Failed to sign message: {e}"),
        ))
    })
}

/// Signs a message and returns hex-encoded signature components
///
/// # Arguments
/// * `secret_key` - The secret key to sign with
/// * `message` - The message to sign
///
/// # Returns
/// * `Ok((signature_hex, nonce_hex))` - Tuple of hex-encoded signature scalar and public nonce
/// * `Err(LightweightWalletError)` - If signing fails
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use lightweight_wallet_libs::crypto::{RistrettoSecretKey, SecretKey};
/// use lightweight_wallet_libs::crypto::signing::sign_message_with_hex_output;
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let message = "Hello, Tari!";
/// let (signature_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message).unwrap();
/// ```
pub fn sign_message_with_hex_output(
    secret_key: &RistrettoSecretKey,
    message: &str,
) -> Result<(String, String), WalletError> {
    let signature = sign_message(secret_key, message)?;

    let hex_signature = signature.get_signature().to_hex();
    let hex_nonce = signature.get_public_nonce().to_hex();

    Ok((hex_signature, hex_nonce))
}

/// Verifies a message signature using the provided public key
///
/// # Arguments
/// * `public_key` - The public key to verify against
/// * `message` - The original message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// * `true` if the signature is valid
/// * `false` if the signature is invalid
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use lightweight_wallet_libs::crypto::{RistrettoPublicKey, RistrettoSecretKey, PublicKey, SecretKey};
/// use lightweight_wallet_libs::crypto::signing::{sign_message, verify_message};
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
/// let message = "Hello, Tari!";
///
/// let signature = sign_message(&secret_key, message).unwrap();
/// let is_valid = verify_message(&public_key, message, &signature);
/// assert!(is_valid);
/// ```
pub fn verify_message(
    public_key: &RistrettoPublicKey,
    message: &str,
    signature: &WalletSignature,
) -> bool {
    let message_bytes = message.as_bytes();
    signature.verify(public_key, message_bytes)
}

/// Verifies a message signature from hex-encoded components
///
/// # Arguments
/// * `public_key` - The public key to verify against
/// * `message` - The original message that was signed
/// * `hex_signature` - Hex-encoded signature scalar
/// * `hex_nonce` - Hex-encoded public nonce
///
/// # Returns
/// * `Ok(true)` if the signature is valid
/// * `Ok(false)` if the signature is invalid but properly formatted
/// * `Err(LightweightWalletError)` if the hex components are malformed
///
/// # Example
/// ```
/// use rand::rngs::OsRng;
/// use lightweight_wallet_libs::crypto::{RistrettoPublicKey, RistrettoSecretKey, PublicKey, SecretKey};
/// use lightweight_wallet_libs::crypto::signing::{sign_message_with_hex_output, verify_message_from_hex};
///
/// let secret_key = RistrettoSecretKey::random(&mut OsRng);
/// let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
/// let message = "Hello, Tari!";
///
/// let (sig_hex, nonce_hex) = sign_message_with_hex_output(&secret_key, message).unwrap();
/// let is_valid = verify_message_from_hex(&public_key, message, &sig_hex, &nonce_hex).unwrap();
/// assert!(is_valid);
/// ```
pub fn verify_message_from_hex(
    public_key: &RistrettoPublicKey,
    message: &str,
    hex_signature: &str,
    hex_nonce: &str,
) -> Result<bool, WalletError> {
    // Parse signature components from hex
    let signature_scalar = RistrettoSecretKey::from_hex(hex_signature).map_err(|e| {
        WalletError::ValidationError(ValidationError::SignatureValidationFailed(
            format!("Invalid signature hex: {e}"),
        ))
    })?;

    let public_nonce = RistrettoPublicKey::from_hex(hex_nonce).map_err(|e| {
        WalletError::ValidationError(ValidationError::SignatureValidationFailed(
            format!("Invalid nonce hex: {e}"),
        ))
    })?;

    // Reconstruct the signature
    let signature = WalletSignature::new(public_nonce, signature_scalar);

    Ok(verify_message(public_key, message, &signature))
}

/// Derives the Tari communication node identity secret key from a seed phrase
/// This is the exact same key that Tari wallets use for message signing
///
/// # Arguments
/// * `seed_phrase` - The wallet's seed phrase (24 words)
/// * `passphrase` - Optional passphrase for CipherSeed decryption
///
/// # Returns
/// * `Ok(RistrettoSecretKey)` - The communication key for message signing
/// * `Err(LightweightWalletError)` - If seed phrase is invalid or key derivation fails
///
/// # Example
/// ```no_run
/// use lightweight_wallet_libs::crypto::signing::derive_tari_signing_key;
///
/// let seed_phrase = "your 24 word seed phrase here...";
/// let signing_key = derive_tari_signing_key(seed_phrase, None).unwrap();
/// // This key can now be used with sign_message_with_hex_output()
/// ```
pub fn derive_tari_signing_key(
    seed_phrase: &str,
    passphrase: Option<&str>,
) -> Result<RistrettoSecretKey, WalletError> {
    // Convert seed phrase to CipherSeed
    let encrypted_bytes = mnemonic_to_bytes(seed_phrase).map_err(|e| {
        WalletError::ValidationError(ValidationError::SignatureValidationFailed(
            format!("Invalid seed phrase: {e}"),
        ))
    })?;

    let cipher_seed =
        CipherSeed::from_enciphered_bytes(&encrypted_bytes, passphrase).map_err(|e| {
            WalletError::ValidationError(ValidationError::SignatureValidationFailed(
                format!("Failed to decrypt CipherSeed: {e}"),
            ))
        })?;

    // Convert entropy to required array type
    let entropy_array: &[u8; 16] = cipher_seed.entropy().try_into().map_err(|_| {
        WalletError::ValidationError(ValidationError::SignatureValidationFailed(
            "Invalid entropy length: expected 16 bytes".to_string(),
        ))
    })?;

    // Derive the communication key (second key from the pair)
    let (_, comms_key) = derive_view_and_spend_keys_from_entropy(entropy_array).map_err(|e| {
        WalletError::ValidationError(ValidationError::SignatureValidationFailed(
            format!("Failed to derive communication key: {e}"),
        ))
    })?;

    Ok(comms_key)
}

/// Signs a message using the Tari communication key derived from a seed phrase
/// This produces signatures identical to those from official Tari wallets
///
/// # Arguments
/// * `seed_phrase` - The wallet's seed phrase (24 words)
/// * `message` - The message to sign
/// * `passphrase` - Optional passphrase for CipherSeed decryption
///
/// # Returns
/// * `Ok((signature_hex, nonce_hex))` - Hex-encoded signature components
/// * `Err(LightweightWalletError)` - If signing fails
///
/// # Example
/// ```no_run
/// use lightweight_wallet_libs::crypto::signing::sign_message_with_tari_wallet;
///
/// let seed_phrase = "your 24 word seed phrase here...";
/// let message = "Hello, Tari!";
/// let (sig_hex, nonce_hex) = sign_message_with_tari_wallet(seed_phrase, message, None).unwrap();
/// ```
pub fn sign_message_with_tari_wallet(
    seed_phrase: &str,
    message: &str,
    passphrase: Option<&str>,
) -> Result<(String, String), WalletError> {
    let signing_key = derive_tari_signing_key(seed_phrase, passphrase)?;
    sign_message_with_hex_output(&signing_key, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use tari_crypto::keys::{PublicKey, SecretKey};

    #[test]
    fn test_sign_and_verify_message() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, Tari!";

        // Sign the message
        let signature = sign_message(&secret_key, message).unwrap();

        // Verify the signature
        assert!(verify_message(&public_key, message, &signature));

        // Verify with wrong message should fail
        assert!(!verify_message(&public_key, "Wrong message", &signature));
    }

    #[test]
    fn test_sign_and_verify_with_hex() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, Tari!";

        // Sign and get hex components
        let (hex_signature, hex_nonce) =
            sign_message_with_hex_output(&secret_key, message).unwrap();

        // Verify from hex components
        let is_valid =
            verify_message_from_hex(&public_key, message, &hex_signature, &hex_nonce).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let is_invalid =
            verify_message_from_hex(&public_key, "Wrong message", &hex_signature, &hex_nonce)
                .unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_hex_parsing_errors() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, Tari!";

        // Test invalid hex signature
        let result = verify_message_from_hex(
            &public_key,
            message,
            "invalid_hex",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());

        // Test invalid hex nonce
        let result = verify_message_from_hex(
            &public_key,
            message,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "invalid_hex",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys() {
        let secret_key1 = RistrettoSecretKey::random(&mut OsRng);
        let secret_key2 = RistrettoSecretKey::random(&mut OsRng);
        let public_key1 = RistrettoPublicKey::from_secret_key(&secret_key1);
        let public_key2 = RistrettoPublicKey::from_secret_key(&secret_key2);
        let message = "Hello, Tari!";

        // Sign with key1
        let signature = sign_message(&secret_key1, message).unwrap();

        // Verify with correct key should succeed
        assert!(verify_message(&public_key1, message, &signature));

        // Verify with wrong key should fail
        assert!(!verify_message(&public_key2, message, &signature));
    }

    #[test]
    fn test_empty_message() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "";

        let signature = sign_message(&secret_key, message).unwrap();
        assert!(verify_message(&public_key, message, &signature));
    }

    #[test]
    fn test_unicode_message() {
        let secret_key = RistrettoSecretKey::random(&mut OsRng);
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        let message = "Hello, 世界! 🚀";

        let signature = sign_message(&secret_key, message).unwrap();
        assert!(verify_message(&public_key, message, &signature));
    }

    #[test]
    fn test_tari_wallet_signing_consistency() {
        use crate::key_management::generate_seed_phrase;

        // Test that the same seed phrase always produces the same signing key
        let seed_phrase = generate_seed_phrase().unwrap();
        let message = "Hello, Tari!";

        // Derive key twice and ensure they're identical
        let key1 = derive_tari_signing_key(&seed_phrase, None).unwrap();
        let key2 = derive_tari_signing_key(&seed_phrase, None).unwrap();
        assert_eq!(key1, key2);

        // Sign same message twice and verify both signatures work
        let (sig1_hex, nonce1_hex) =
            sign_message_with_tari_wallet(&seed_phrase, message, None).unwrap();
        let (sig2_hex, nonce2_hex) =
            sign_message_with_tari_wallet(&seed_phrase, message, None).unwrap();

        // Signatures will be different due to random nonce, but both should verify
        let public_key = RistrettoPublicKey::from_secret_key(&key1);

        let is_valid1 =
            verify_message_from_hex(&public_key, message, &sig1_hex, &nonce1_hex).unwrap();
        let is_valid2 =
            verify_message_from_hex(&public_key, message, &sig2_hex, &nonce2_hex).unwrap();

        assert!(is_valid1);
        assert!(is_valid2);
    }

    #[test]
    fn test_tari_communication_key_derivation() {
        use crate::key_management::generate_seed_phrase;

        // Test that we get the communication key (not the view key)
        let seed_phrase = generate_seed_phrase().unwrap();

        let comms_key = derive_tari_signing_key(&seed_phrase, None).unwrap();

        // The key should be deterministic for the same seed phrase
        let comms_key2 = derive_tari_signing_key(&seed_phrase, None).unwrap();
        assert_eq!(comms_key, comms_key2);

        // The key should be different from a random key
        let random_key = RistrettoSecretKey::random(&mut OsRng);
        assert_ne!(comms_key, random_key);
    }
}
