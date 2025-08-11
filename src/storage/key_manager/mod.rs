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
}

#[allow(unused)]
impl TransactionKeyManagerSqliteDatabase {
    /// Creates a new sql backend from provided wallet db connection
    /// * `cipher` is used to encrypt the sensitive fields in the database, a cipher is derived
    /// * from a provided password, which we enforce for class instantiation
    fn new(database_connection: SqliteStorage, cipher: XChaCha20Poly1305) -> Self {
        Self {
            database_connection: Arc::new(database_connection),
            cipher: Arc::new(RwLock::new(cipher)),
        }
    }
}

impl TransactionKeyManagerBackend for TransactionKeyManagerSqliteDatabase {
    fn get_key_manager(
        &self,
        branch: &str,
    ) -> Result<Option<KeyManagerState>, KeyManagerStorageError> {
        let result = match Handle::current()
            .block_on(self.database_connection.key_manager_get_state(branch))
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

        let km_sql = NewKeyManagerStateSql::from(key_manager);
        let km_sql = km_sql
            .encrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Encryption Error: {}", e)))?;
        Handle::current()
            .block_on(self.database_connection.key_manager_commit_state(&km_sql))
            .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))
    }

    fn increment_key_index(&self, branch: &str) -> Result<(), KeyManagerStorageError> {
        let cipher = self.cipher.read().unwrap();
        let km = Handle::current()
            .block_on(self.database_connection.key_manager_get_state(branch))
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
        Handle::current()
            .block_on(
                self.database_connection
                    .key_manager_set_index(km.id, km.primary_key_index),
            )
            .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))
    }

    fn set_key_index(&self, branch: &str, index: u64) -> Result<(), KeyManagerStorageError> {
        let cipher = self.cipher.read().unwrap();
        let km = Handle::current()
            .block_on(self.database_connection.key_manager_get_state(branch))
            .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))?;
        let mut km = km
            .decrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Decryption Error: {}", e)))?;
        km.primary_key_index = index.to_le_bytes().to_vec();
        let km = km
            .encrypt(&cipher)
            .map_err(|e| KeyManagerStorageError::AeadError(format!("Encryption Error: {}", e)))?;
        Handle::current()
            .block_on(
                self.database_connection
                    .key_manager_set_index(km.id, km.primary_key_index),
            )
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
        let encrypted_key = NewImportedKeySql::new_from_imported_key(key, &cipher)?;
        Handle::current()
            .block_on(
                self.database_connection
                    .key_manager_commit_imported_key(&encrypted_key),
            )
            .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))
    }

    fn get_imported_key(
        &self,
        public_key: &CompressedPublicKey,
    ) -> Result<PrivateKey, KeyManagerStorageError> {
        let cipher = self.cipher.read().unwrap();
        let key = Handle::current()
            .block_on(
                self.database_connection
                    .key_manager_get_imported_key(public_key),
            )
            .map_err(|e| KeyManagerStorageError::StorageError(e.to_string()))?;
        let unencrypted_key = key.to_imported_key(&cipher)?;
        Ok(unencrypted_key.private_key)
    }
}
