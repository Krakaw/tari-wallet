pub mod imported_keys;
pub mod key_manager_state;

use std::sync::{Arc, RwLock};
use tokio::runtime::Handle;

use crate::storage::storage_trait::WalletStorage;
use chacha20poly1305::XChaCha20Poly1305;
pub use imported_keys::*;
pub use key_manager_state::*;
use tari_common_types::{
    encryption::Encryptable,
    types::{CompressedPublicKey, PrivateKey},
};
use tari_transaction_components::key_manager::{
    error::KeyManagerStorageError, KeyManagerState, TransactionKeyManagerBackend,
};

use crate::SqliteStorage;

/// A Sqlite backend for the Output Manager Service.
#[derive(Clone)]
pub struct TransactionKeyManagerSqliteDatabase {
    database_connection: Arc<SqliteStorage>,
    cipher: Arc<RwLock<XChaCha20Poly1305>>,
    wallet_id: u32,
}

#[allow(unused)]
impl TransactionKeyManagerSqliteDatabase {
    /// Creates a new sql backend from provided wallet db connection
    /// * `cipher` is used to encrypt the sensitive fields in the database
    pub fn new(
        database_connection: SqliteStorage,
        cipher: XChaCha20Poly1305,
        wallet_id: u32,
    ) -> Self {
        Self {
            database_connection: Arc::new(database_connection),
            cipher: Arc::new(RwLock::new(cipher)),
            wallet_id,
        }
    }
}

impl TransactionKeyManagerBackend for TransactionKeyManagerSqliteDatabase {
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
    use crate::{storage::StoredWallet, SqliteStorage};
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

    async fn setup_db() -> TransactionKeyManagerSqliteDatabase {
        let db = SqliteStorage::new_in_memory().await.unwrap();
        db.initialize().await.unwrap();

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let key_ga = Key::from_slice(&key);
        let cipher = XChaCha20Poly1305::new(key_ga);

        let wallet_id = create_test_wallet(&db).await;
        TransactionKeyManagerSqliteDatabase::new(db, cipher, wallet_id)
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
}
