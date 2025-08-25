use std::sync::{Arc, RwLock};

use chacha20poly1305::{Key, KeyInit};
use tokio::runtime::Handle;

use crate::{
    key_manager::{ImportedKey, NewImportedKeySql, NewKeyManagerStateSql},
    storage::storage_trait::WalletStorage,
};
use chacha20poly1305::XChaCha20Poly1305;
use tari_common_types::{
    encryption::Encryptable,
    types::{CompressedPublicKey, PrivateKey},
};
use tari_transaction_components::key_manager::{
    error::KeyManagerStorageError, KeyManagerState, TransactionKeyManagerBackend,
};
use tari_utilities::hex::Hex;

/// A Sqlite backend for the Output Manager Service.
#[derive(Clone)]
pub struct TransactionKeyManagerWalletStorage {
    database_connection: Arc<dyn WalletStorage>,
    cipher: Arc<RwLock<XChaCha20Poly1305>>,
    wallet_id: u32,
}

#[allow(unused)]
impl TransactionKeyManagerWalletStorage {
    /// Creates a new sql backend from provided wallet db connection
    /// * `cipher` is used to encrypt the sensitive fields in the database
    pub fn new(
        database_connection: Arc<dyn WalletStorage>,
        cipher: XChaCha20Poly1305,
        wallet_id: u32,
    ) -> Self {
        Self {
            database_connection,
            cipher: Arc::new(RwLock::new(cipher)),
            wallet_id,
        }
    }

    pub async fn build(
        database_connection: Arc<dyn WalletStorage>,
        wallet_id: u32,
    ) -> Result<Self, KeyManagerStorageError> {
        let wallet = database_connection
            .get_wallet_by_id(wallet_id)
            .await
            .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))?
            .ok_or(KeyManagerStorageError::StorageError(
                "Wallet not found".to_string(),
            ))?;

        let key_bytes = Vec::from_hex(&wallet.view_key_hex)
            .map_err(|e| KeyManagerStorageError::AeadError(e.to_string()))?;
        let key = Key::from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new(key);

        Ok(Self::new(database_connection, cipher, wallet_id))
    }
}

impl TransactionKeyManagerBackend for TransactionKeyManagerWalletStorage {
    fn get_key_manager(
        &self,
        branch: &str,
    ) -> Result<Option<KeyManagerState>, KeyManagerStorageError> {
        let result = match tokio::task::block_in_place(|| {
            Handle::current().block_on(
                self.database_connection
                    .key_manager_get_state(branch, self.wallet_id),
            )
        })
        .ok()
        {
            None => None,
            Some(km) => {
                let cipher = self.cipher.read().unwrap();
                let km = km.decrypt(&cipher).map_err(|e| {
                    KeyManagerStorageError::AeadError(format!("Decryption Error: {}", e))
                })?;
                Some(KeyManagerState::try_from(km)?)
            }
        };
        Ok(result)
    }

    fn add_key_manager(&self, key_manager: KeyManagerState) -> Result<(), KeyManagerStorageError> {
        let cipher = self.cipher.read().unwrap();

        let km_sql = NewKeyManagerStateSql::new(key_manager, self.wallet_id);
        let km_sql = km_sql
            .encrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Encryption Error: {}", e)))?;
        tokio::task::block_in_place(|| {
            Handle::current().block_on(self.database_connection.key_manager_commit_state(&km_sql))
        })
        .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn increment_key_index(&self, branch: &str) -> Result<(), KeyManagerStorageError> {
        let cipher = self.cipher.read().unwrap();
        let km = tokio::task::block_in_place(|| {
            Handle::current().block_on(
                self.database_connection
                    .key_manager_get_state(branch, self.wallet_id),
            )
        })
        .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))?;
        let mut km = km
            .decrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Decryption Error: {}", e)))?;
        let mut bytes: [u8; 8] = [0u8; 8];
        bytes.copy_from_slice(&km.primary_key_index[..8]);
        let index = u64::from_le_bytes(bytes) + 1;
        km.primary_key_index = index.to_le_bytes().to_vec();
        let km = km
            .encrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Encryption Error: {}", e)))?;
        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                self.database_connection
                    .key_manager_set_index(km.id, km.primary_key_index),
            )
        })
        .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))
    }

    fn set_key_index(&self, branch: &str, index: u64) -> Result<(), KeyManagerStorageError> {
        let cipher = self.cipher.read().unwrap();
        let km = tokio::task::block_in_place(|| {
            Handle::current().block_on(
                self.database_connection
                    .key_manager_get_state(branch, self.wallet_id),
            )
        })
        .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))?;
        let mut km = km
            .decrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Decryption Error: {}", e)))?;
        km.primary_key_index = index.to_le_bytes().to_vec();
        let km = km
            .encrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Encryption Error: {}", e)))?;
        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                self.database_connection
                    .key_manager_set_index(km.id, km.primary_key_index),
            )
        })
        .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))
    }

    fn insert_imported_key(
        &self,
        public_key: CompressedPublicKey,
        private_key: PrivateKey,
    ) -> Result<(), KeyManagerStorageError> {
        // check if we already have the key:
        if self.get_imported_key(&public_key).is_ok() {
            // we already have the key so we dont have to add it in
            return Ok(());
        }
        let cipher = self.cipher.read().unwrap();
        let key = ImportedKey {
            public_key,
            private_key,
        };
        let encrypted_key = NewImportedKeySql::new_from_imported_key(key, self.wallet_id, &cipher)?;
        tokio::task::block_in_place(|| {
            Handle::current().block_on(
                self.database_connection
                    .key_manager_commit_imported_key(&encrypted_key),
            )
        })
        .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))
    }

    fn get_imported_key(
        &self,
        public_key: &CompressedPublicKey,
    ) -> Result<PrivateKey, KeyManagerStorageError> {
        let cipher = self.cipher.read().unwrap();
        let key = tokio::task::block_in_place(|| {
            Handle::current().block_on(
                self.database_connection
                    .key_manager_get_imported_key(public_key, self.wallet_id),
            )
        })
        .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))?;
        let unencrypted_key = key.to_imported_key(&cipher)?;
        Ok(unencrypted_key.private_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{storage::StoredWallet, CipherSeed, SqliteStorage};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
    use rand::{rngs::OsRng, RngCore};
    use tari_common_types::types::{CompressedPublicKey, PrivateKey};
    use tari_transaction_components::key_manager::KeyManagerState;
    use tari_utilities::hex::Hex;

    async fn create_test_wallet(storage: &SqliteStorage) -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_wallet = StoredWallet {
            id: None,
            name: format!("test_wallet_{}_{}", std::process::id(), timestamp),
            master_key: CipherSeed::new(),
            seed_phrase: None,
            view_key_hex: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            spend_key_hex: None,
            birthday_block: 0,
            latest_scanned_block: None,
            created_at: None,
            updated_at: None,
        };
        storage.save_wallet(&test_wallet).await.unwrap()
    }

    async fn setup_db() -> TransactionKeyManagerWalletStorage {
        let db = SqliteStorage::new_in_memory().await.unwrap();
        db.initialize().await.unwrap();

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let key_ga = Key::from_slice(&key);
        let cipher = XChaCha20Poly1305::new(key_ga);

        let wallet_id = create_test_wallet(&db).await;
        TransactionKeyManagerWalletStorage::new(Arc::new(db), cipher, wallet_id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_key_manager_crud() {
        let km_db = setup_db().await;

        // Test get_key_manager on empty DB
        assert!(km_db.get_key_manager("test_branch").unwrap().is_none());

        // Test add_key_manager
        let initial_state = KeyManagerState {
            branch_seed: "test_branch".to_string(),
            primary_key_index: 10,
        };
        km_db.add_key_manager(initial_state.clone()).unwrap();

        // Test get_key_manager after adding
        let fetched_state = km_db.get_key_manager("test_branch").unwrap().unwrap();
        assert_eq!(fetched_state.branch_seed, initial_state.branch_seed);
        assert_eq!(
            fetched_state.primary_key_index,
            initial_state.primary_key_index
        );

        // Test increment_key_index
        km_db.increment_key_index("test_branch").unwrap();
        let state_after_increment = km_db.get_key_manager("test_branch").unwrap().unwrap();
        assert_eq!(state_after_increment.primary_key_index, 11);

        // Test set_key_index
        km_db.set_key_index("test_branch", 25).unwrap();
        let state_after_set = km_db.get_key_manager("test_branch").unwrap().unwrap();
        assert_eq!(state_after_set.primary_key_index, 25);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_imported_keys_crud() {
        let km_db = setup_db().await;

        // Generate a test key pair
        let private_key = PrivateKey::from_hex(
            "6e43d7563adfc5a325864a3354ad645a2e83a86a39342448b54b255244203707",
        )
        .unwrap();
        let public_key = CompressedPublicKey::from_secret_key(&private_key);

        // Test insert_imported_key
        km_db
            .insert_imported_key(public_key.clone(), private_key.clone())
            .unwrap();

        // Test get_imported_key
        let fetched_private_key = km_db.get_imported_key(&public_key).unwrap();
        assert_eq!(fetched_private_key, private_key);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_build_and_cipher_consistency() {
        let db = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
        db.initialize().await.unwrap();

        // Create a test wallet
        let wallet_id = create_test_wallet(&db).await;

        // Create the first key manager instance
        let km_db1 = TransactionKeyManagerWalletStorage::build(db.clone(), wallet_id)
            .await
            .unwrap();

        // Create the second key manager instance for the same wallet
        let km_db2 = TransactionKeyManagerWalletStorage::build(db, wallet_id)
            .await
            .unwrap();

        // Test KeyManagerState encryption/decryption
        let initial_state = KeyManagerState {
            branch_seed: "test_branch_1".to_string(),
            primary_key_index: 10,
        };
        km_db1.add_key_manager(initial_state.clone()).unwrap();

        let fetched_state_from_db2 = km_db2.get_key_manager("test_branch_1").unwrap().unwrap();
        assert_eq!(
            fetched_state_from_db2.branch_seed,
            initial_state.branch_seed
        );
        assert_eq!(
            fetched_state_from_db2.primary_key_index,
            initial_state.primary_key_index
        );

        // Test imported key encryption/decryption
        let private_key = PrivateKey::from_hex(
            "6e43d7563adfc5a325864a3354ad645a2e83a86a39342448b54b255244203707",
        )
        .unwrap();
        let public_key = CompressedPublicKey::from_secret_key(&private_key);

        km_db1
            .insert_imported_key(public_key.clone(), private_key.clone())
            .unwrap();

        let fetched_private_key_from_db2 = km_db2.get_imported_key(&public_key).unwrap();
        assert_eq!(fetched_private_key_from_db2, private_key);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_build_non_existent_wallet() {
        let db = Arc::new(SqliteStorage::new_in_memory().await.unwrap());
        db.initialize().await.unwrap();

        // Attempt to build with a non-existent wallet ID
        let result = TransactionKeyManagerWalletStorage::build(db, 999).await;
        assert!(result.is_err());
    }
}
