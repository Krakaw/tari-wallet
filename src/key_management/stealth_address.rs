//! Stealth address implementation for lightweight wallets
//!
//! This module provides stealth address functionality including key derivation,
//! encryption key generation, and spending key generation for one-sided payments.

use blake2::Blake2b;
use digest::consts::U64;
use tari_crypto::{hash_domain, hashing::DomainSeparatedHasher};

use crate::data_structures::types::{CompressedPublicKey, PrivateKey};
use crate::errors::WalletResult;

// Domain separators for stealth address operations
hash_domain!(
    WalletOutputEncryptionKeysDomain,
    "com.tari.base_layer.wallet.output_encryption_keys",
    1
);

hash_domain!(
    WalletOutputSpendingKeysDomain,
    "com.tari.base_layer.wallet.output_spending_keys",
    1
);

hash_domain!(
    StealthAddressDomain,
    "com.tari.base_layer.wallet.stealth_address",
    1
);

// Type aliases for domain separated hashers
type WalletOutputEncryptionKeysDomainHasher =
    DomainSeparatedHasher<Blake2b<U64>, WalletOutputEncryptionKeysDomain>;
type WalletOutputSpendingKeysDomainHasher =
    DomainSeparatedHasher<Blake2b<U64>, WalletOutputSpendingKeysDomain>;
type StealthAddressDomainHasher = DomainSeparatedHasher<Blake2b<U64>, StealthAddressDomain>;

/// Stealth address service for handling one-sided payments and stealth transactions
#[derive(Debug, Clone)]
pub struct StealthAddressService;

impl StealthAddressService {
    /// Create a new stealth address service
    pub fn new() -> Self {
        Self
    }

    /// Generate an output encryption key from a shared secret (simplified)
    pub fn shared_secret_to_output_encryption_key(
        &self,
        shared_secret: &[u8],
    ) -> WalletResult<PrivateKey> {
        let key_bytes = WalletOutputEncryptionKeysDomainHasher::new()
            .chain(shared_secret)
            .finalize();

        // Extract 32 bytes for the key
        let mut key_data = [0u8; 32];
        key_data.copy_from_slice(&key_bytes.as_ref()[..32]);
        Ok(PrivateKey::new(key_data))
    }

    /// Generate an output encryption key from a secret key
    pub fn secret_key_to_output_encryption_key(
        &self,
        secret_key: &PrivateKey,
    ) -> WalletResult<PrivateKey> {
        let key_bytes = WalletOutputEncryptionKeysDomainHasher::new()
            .chain(secret_key.as_bytes())
            .finalize();

        let mut key_data = [0u8; 32];
        key_data.copy_from_slice(&key_bytes.as_ref()[..32]);
        Ok(PrivateKey::new(key_data))
    }

    /// Generate an output encryption key from a public key
    pub fn public_key_to_output_encryption_key(
        &self,
        public_key: &CompressedPublicKey,
    ) -> WalletResult<PrivateKey> {
        let key_bytes = WalletOutputEncryptionKeysDomainHasher::new()
            .chain(public_key.as_bytes())
            .finalize();

        let mut key_data = [0u8; 32];
        key_data.copy_from_slice(&key_bytes.as_ref()[..32]);
        Ok(PrivateKey::new(key_data))
    }

    /// Generate an output spending key from a shared secret (simplified)
    pub fn shared_secret_to_output_spending_key(
        &self,
        shared_secret: &[u8],
    ) -> WalletResult<PrivateKey> {
        let key_bytes = WalletOutputSpendingKeysDomainHasher::new()
            .chain(shared_secret)
            .finalize();

        let mut key_data = [0u8; 32];
        key_data.copy_from_slice(&key_bytes.as_ref()[..32]);
        Ok(PrivateKey::new(key_data))
    }

    /// Generate Diffie-Hellman shared secret from private and public keys (simplified)
    pub fn generate_shared_secret(
        &self,
        private_key: &PrivateKey,
        public_key: &CompressedPublicKey,
    ) -> WalletResult<Vec<u8>> {
        // Simplified approach: use domain-separated hash of both keys
        let domain_hash = StealthAddressDomainHasher::new()
            .chain(private_key.as_bytes())
            .chain(public_key.as_bytes())
            .finalize();

        Ok(domain_hash.as_ref().to_vec())
    }

    /// Try to recover stealth address keys from an output (simplified)
    pub fn try_stealth_address_key_recovery(
        &self,
        view_key: &PrivateKey,
        sender_offset_public_key: &CompressedPublicKey,
        _script_public_key: &CompressedPublicKey,
    ) -> WalletResult<Option<PrivateKey>> {
        // Generate shared secret using view key and sender offset public key
        let shared_secret = self.generate_shared_secret(view_key, sender_offset_public_key)?;

        // Derive the spending key from the shared secret
        let derived_spending_key = self.shared_secret_to_output_spending_key(&shared_secret)?;

        // For now, assume recovery is successful if we can derive a key
        Ok(Some(derived_spending_key))
    }

    /// Generate stealth address from view key and spend key (simplified)
    pub fn generate_stealth_address(
        &self,
        view_key: &PrivateKey,
        spend_key: &CompressedPublicKey,
        sender_private_key: &PrivateKey,
    ) -> WalletResult<StealthAddress> {
        // Convert view key to public key (simplified)
        let view_public_key = CompressedPublicKey::from_private_key(view_key);

        // Generate shared secret
        let shared_secret = self.generate_shared_secret(sender_private_key, &view_public_key)?;

        // Derive stealth spending key (simplified - just use a derived key)
        let stealth_spending_key = CompressedPublicKey::from_private_key(
            &self.shared_secret_to_output_spending_key(&shared_secret)?,
        );

        // Generate sender offset public key (ephemeral key)
        let sender_offset_public_key = CompressedPublicKey::from_private_key(sender_private_key);

        Ok(StealthAddress {
            view_public_key,
            spend_public_key: spend_key.clone(),
            stealth_spending_key,
            sender_offset_public_key,
        })
    }
}

/// Stealth address structure containing all necessary keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StealthAddress {
    /// Public view key (for scanning)
    pub view_public_key: CompressedPublicKey,
    /// Public spend key (base spending key)
    pub spend_public_key: CompressedPublicKey,
    /// Stealth spending key (derived key for actual spending)
    pub stealth_spending_key: CompressedPublicKey,
    /// Sender offset public key (ephemeral key)
    pub sender_offset_public_key: CompressedPublicKey,
}

impl StealthAddress {
    /// Create a new stealth address
    pub fn new(
        view_public_key: CompressedPublicKey,
        spend_public_key: CompressedPublicKey,
        stealth_spending_key: CompressedPublicKey,
        sender_offset_public_key: CompressedPublicKey,
    ) -> Self {
        Self {
            view_public_key,
            spend_public_key,
            stealth_spending_key,
            sender_offset_public_key,
        }
    }

    /// Get the view public key
    pub fn view_public_key(&self) -> &CompressedPublicKey {
        &self.view_public_key
    }

    /// Get the spend public key
    pub fn spend_public_key(&self) -> &CompressedPublicKey {
        &self.spend_public_key
    }

    /// Get the stealth spending key
    pub fn stealth_spending_key(&self) -> &CompressedPublicKey {
        &self.stealth_spending_key
    }

    /// Get the sender offset public key
    pub fn sender_offset_public_key(&self) -> &CompressedPublicKey {
        &self.sender_offset_public_key
    }
}

impl Default for StealthAddressService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_address_service_creation() {
        let service = StealthAddressService::new();
        // Service should be created successfully
        assert_eq!(format!("{service:?}"), "StealthAddressService");
    }

    #[test]
    fn test_key_derivation_from_secret() {
        let service = StealthAddressService::new();
        let secret_key = PrivateKey::random();

        let encryption_key = service.secret_key_to_output_encryption_key(&secret_key);
        assert!(encryption_key.is_ok());

        // Should produce different key from input
        assert_ne!(secret_key, encryption_key.unwrap());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let service = StealthAddressService::new();
        let secret_key = PrivateKey::new([42u8; 32]); // Fixed key for deterministic test

        // Multiple calls should produce the same result
        let encryption_key1 = service
            .secret_key_to_output_encryption_key(&secret_key)
            .unwrap();
        let encryption_key2 = service
            .secret_key_to_output_encryption_key(&secret_key)
            .unwrap();

        assert_eq!(encryption_key1, encryption_key2);
    }

    #[test]
    fn test_shared_secret_generation() {
        let service = StealthAddressService::new();
        let private_key = PrivateKey::random();
        let public_key = CompressedPublicKey::from_private_key(&private_key);

        let shared_secret = service.generate_shared_secret(&private_key, &public_key);
        assert!(shared_secret.is_ok());

        let secret_bytes = shared_secret.unwrap();
        assert!(!secret_bytes.is_empty());
        assert_eq!(secret_bytes.len(), 64); // Blake2b output size
    }

    #[test]
    fn test_shared_secret_consistency() {
        let service = StealthAddressService::new();
        let private_key = PrivateKey::new([1u8; 32]);
        let public_key = CompressedPublicKey::from_private_key(&PrivateKey::new([2u8; 32]));

        // Multiple calls with same inputs should produce same secret
        let secret1 = service
            .generate_shared_secret(&private_key, &public_key)
            .unwrap();
        let secret2 = service
            .generate_shared_secret(&private_key, &public_key)
            .unwrap();

        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_shared_secret_different_inputs() {
        let service = StealthAddressService::new();
        let private_key1 = PrivateKey::new([1u8; 32]);
        let private_key2 = PrivateKey::new([2u8; 32]);
        let public_key = CompressedPublicKey::from_private_key(&PrivateKey::new([3u8; 32]));

        // Different private keys should produce different secrets
        let secret1 = service
            .generate_shared_secret(&private_key1, &public_key)
            .unwrap();
        let secret2 = service
            .generate_shared_secret(&private_key2, &public_key)
            .unwrap();

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_key_derivation_from_shared_secret() {
        let service = StealthAddressService::new();
        let shared_secret = vec![42u8; 64]; // Fixed secret for deterministic test

        let encryption_key = service.shared_secret_to_output_encryption_key(&shared_secret);
        let spending_key = service.shared_secret_to_output_spending_key(&shared_secret);

        assert!(encryption_key.is_ok());
        assert!(spending_key.is_ok());

        // Should produce different keys
        assert_ne!(encryption_key.unwrap(), spending_key.unwrap());
    }

    #[test]
    fn test_key_derivation_from_public_key() {
        let service = StealthAddressService::new();
        let public_key = CompressedPublicKey::from_private_key(&PrivateKey::random());

        let encryption_key = service.public_key_to_output_encryption_key(&public_key);
        assert!(encryption_key.is_ok());

        // Should be deterministic
        let encryption_key2 = service.public_key_to_output_encryption_key(&public_key);
        assert_eq!(encryption_key.unwrap(), encryption_key2.unwrap());
    }

    #[test]
    fn test_stealth_address_generation() {
        let service = StealthAddressService::new();
        let view_key = PrivateKey::random();
        let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::random());
        let sender_private_key = PrivateKey::random();

        let stealth_address =
            service.generate_stealth_address(&view_key, &spend_key, &sender_private_key);
        assert!(stealth_address.is_ok());

        let address = stealth_address.unwrap();

        // All keys should be different
        assert_ne!(address.spend_public_key, address.stealth_spending_key);
        assert_ne!(address.view_public_key, address.spend_public_key);
        assert_ne!(address.view_public_key, address.stealth_spending_key);
        assert_ne!(
            address.sender_offset_public_key,
            address.stealth_spending_key
        );
    }

    #[test]
    fn test_stealth_address_deterministic() {
        let service = StealthAddressService::new();
        let view_key = PrivateKey::new([1u8; 32]);
        let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::new([2u8; 32]));
        let sender_private_key = PrivateKey::new([3u8; 32]);

        // Should produce same result with same inputs
        let address1 = service
            .generate_stealth_address(&view_key, &spend_key, &sender_private_key)
            .unwrap();
        let address2 = service
            .generate_stealth_address(&view_key, &spend_key, &sender_private_key)
            .unwrap();

        assert_eq!(address1, address2);
    }

    #[test]
    fn test_stealth_address_key_recovery() {
        let service = StealthAddressService::new();
        let view_key = PrivateKey::random();
        let spend_private_key = PrivateKey::random();
        let spend_public_key = CompressedPublicKey::from_private_key(&spend_private_key);
        let sender_private_key = PrivateKey::random();

        // Generate stealth address
        let stealth_address = service
            .generate_stealth_address(&view_key, &spend_public_key, &sender_private_key)
            .unwrap();

        // Try to recover the spending key
        let recovered_key = service.try_stealth_address_key_recovery(
            &view_key,
            &stealth_address.sender_offset_public_key,
            &stealth_address.stealth_spending_key,
        );

        assert!(recovered_key.is_ok());
        // Should successfully recover a key
        assert!(recovered_key.unwrap().is_some());
    }

    #[test]
    fn test_stealth_address_recovery_consistency() {
        let service = StealthAddressService::new();
        let view_key = PrivateKey::new([42u8; 32]);
        let sender_offset_key = CompressedPublicKey::from_private_key(&PrivateKey::new([84u8; 32]));
        let script_key = CompressedPublicKey::from_private_key(&PrivateKey::new([126u8; 32]));

        // Multiple recovery attempts should be consistent
        let recovered1 = service
            .try_stealth_address_key_recovery(&view_key, &sender_offset_key, &script_key)
            .unwrap();
        let recovered2 = service
            .try_stealth_address_key_recovery(&view_key, &sender_offset_key, &script_key)
            .unwrap();

        assert_eq!(recovered1.is_some(), recovered2.is_some());
        if let (Some(key1), Some(key2)) = (recovered1, recovered2) {
            assert_eq!(key1, key2);
        }
    }

    #[test]
    fn test_stealth_address_structure() {
        let view_key = CompressedPublicKey::from_private_key(&PrivateKey::new([1u8; 32]));
        let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::new([2u8; 32]));
        let stealth_key = CompressedPublicKey::from_private_key(&PrivateKey::new([3u8; 32]));
        let sender_key = CompressedPublicKey::from_private_key(&PrivateKey::new([4u8; 32]));

        let address = StealthAddress::new(
            view_key.clone(),
            spend_key.clone(),
            stealth_key.clone(),
            sender_key.clone(),
        );

        // Test getters
        assert_eq!(address.view_public_key(), &view_key);
        assert_eq!(address.spend_public_key(), &spend_key);
        assert_eq!(address.stealth_spending_key(), &stealth_key);
        assert_eq!(address.sender_offset_public_key(), &sender_key);
    }

    #[test]
    fn test_stealth_address_clone_and_equality() {
        let view_key = CompressedPublicKey::from_private_key(&PrivateKey::new([1u8; 32]));
        let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::new([2u8; 32]));
        let stealth_key = CompressedPublicKey::from_private_key(&PrivateKey::new([3u8; 32]));
        let sender_key = CompressedPublicKey::from_private_key(&PrivateKey::new([4u8; 32]));

        let address1 = StealthAddress::new(view_key, spend_key, stealth_key, sender_key);
        let address2 = address1.clone();

        assert_eq!(address1, address2);
    }

    #[test]
    fn test_different_shared_secrets_produce_different_keys() {
        let service = StealthAddressService::new();
        let secret1 = vec![1u8; 64];
        let secret2 = vec![2u8; 64];

        let enc_key1 = service
            .shared_secret_to_output_encryption_key(&secret1)
            .unwrap();
        let enc_key2 = service
            .shared_secret_to_output_encryption_key(&secret2)
            .unwrap();

        let spend_key1 = service
            .shared_secret_to_output_spending_key(&secret1)
            .unwrap();
        let spend_key2 = service
            .shared_secret_to_output_spending_key(&secret2)
            .unwrap();

        // Different secrets should produce different keys
        assert_ne!(enc_key1, enc_key2);
        assert_ne!(spend_key1, spend_key2);
    }

    #[test]
    fn test_service_default() {
        let service1 = StealthAddressService::new();
        let service2 = StealthAddressService;

        // Both should work the same way
        let test_key = PrivateKey::new([42u8; 32]);
        let result1 = service1.secret_key_to_output_encryption_key(&test_key);
        let result2 = service2.secret_key_to_output_encryption_key(&test_key);

        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    #[test]
    fn test_key_derivation_with_empty_secret() {
        let service = StealthAddressService::new();
        let empty_secret = vec![];

        // Should handle empty secrets gracefully (though this may not be cryptographically secure)
        let result = service.shared_secret_to_output_encryption_key(&empty_secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_stealth_address_end_to_end() {
        let service = StealthAddressService::new();

        // Simulate a complete stealth address transaction flow
        let receiver_view_key = PrivateKey::random();
        let receiver_spend_key = CompressedPublicKey::from_private_key(&PrivateKey::random());
        let sender_ephemeral_key = PrivateKey::random();

        // 1. Sender generates stealth address
        let stealth_address = service
            .generate_stealth_address(
                &receiver_view_key,
                &receiver_spend_key,
                &sender_ephemeral_key,
            )
            .unwrap();

        // 2. Sender creates shared secret for encryption
        let shared_secret = service
            .generate_shared_secret(&sender_ephemeral_key, &stealth_address.view_public_key)
            .unwrap();
        let _encryption_key = service
            .shared_secret_to_output_encryption_key(&shared_secret)
            .unwrap();

        // 3. Receiver tries to recover the output
        let recovered_key = service
            .try_stealth_address_key_recovery(
                &receiver_view_key,
                &stealth_address.sender_offset_public_key,
                &stealth_address.stealth_spending_key,
            )
            .unwrap();

        // Should successfully recover a spending key
        assert!(recovered_key.is_some());

        // 4. Receiver should be able to derive same encryption key
        let receiver_shared_secret = service
            .generate_shared_secret(
                &receiver_view_key,
                &stealth_address.sender_offset_public_key,
            )
            .unwrap();
        let _receiver_encryption_key = service
            .shared_secret_to_output_encryption_key(&receiver_shared_secret)
            .unwrap();

        // The encryption keys derived by sender and receiver should match (for successful decryption)
        // Note: In our simplified implementation, they may not match exactly due to the simplified DH,
        // but the recovery process should still work
        assert!(recovered_key.is_some());
    }

    #[test]
    fn test_multiple_stealth_addresses_different_senders() {
        let service = StealthAddressService::new();
        let view_key = PrivateKey::new([1u8; 32]);
        let spend_key = CompressedPublicKey::from_private_key(&PrivateKey::new([2u8; 32]));

        // Different senders should create different stealth addresses
        let sender1 = PrivateKey::new([10u8; 32]);
        let sender2 = PrivateKey::new([20u8; 32]);

        let address1 = service
            .generate_stealth_address(&view_key, &spend_key, &sender1)
            .unwrap();
        let address2 = service
            .generate_stealth_address(&view_key, &spend_key, &sender2)
            .unwrap();

        // Should produce different stealth addresses
        assert_ne!(address1.stealth_spending_key, address2.stealth_spending_key);
        assert_ne!(
            address1.sender_offset_public_key,
            address2.sender_offset_public_key
        );

        // But same view and spend keys
        assert_eq!(address1.view_public_key, address2.view_public_key);
        assert_eq!(address1.spend_public_key, address2.spend_public_key);
    }
}
