use chacha20poly1305::XChaCha20Poly1305;
use chrono::{NaiveDateTime, Utc};
use rusqlite::{params, Row};
use tari_common_types::{
    encryption::{decrypt_bytes_integral_nonce, encrypt_bytes_integral_nonce, Encryptable},
    types::{CompressedPublicKey, PrivateKey},
};
use tari_transaction_components::key_manager::error::KeyManagerStorageError;
use tari_utilities::{hex::Hex, ByteArray, Hidden};
use tokio_rusqlite::Connection;
use zeroize::Zeroize;

const DOMAIN: &[u8; 11] = b"KEY_MANAGER";

/// Holds the state of the KeyManager for the branch
#[derive(Clone, Debug, PartialEq)]
pub struct ImportedKey {
    pub private_key: PrivateKey,
    pub public_key: CompressedPublicKey,
}

/// Represents a row in the imported keys table.
#[derive(Clone, Debug)]
pub struct ImportedKeySql {
    pub id: i32,
    pub wallet_id: u32,
    pub private_key: Vec<u8>,
    pub public_key: String,
    pub timestamp: NaiveDateTime,
}

/// Struct used to create a new Key manager in the database
#[derive(Clone, Debug)]
pub struct NewImportedKeySql {
    pub wallet_id: u32,
    pub private_key: Vec<u8>,
    pub public_key: String,
    pub timestamp: NaiveDateTime,
}

impl NewImportedKeySql {
    // Creates a new ImportedKey with encrypted values
    pub fn new_from_imported_key(
        key: ImportedKey,
        wallet_id: u32,
        cipher: &XChaCha20Poly1305,
    ) -> Result<Self, KeyManagerStorageError> {
        let imported_key_sql = NewImportedKeySql {
            wallet_id,
            private_key: key.private_key.to_vec(),
            public_key: key.public_key.to_hex(),
            timestamp: Utc::now().naive_utc(),
        };
        let key = imported_key_sql
            .encrypt(cipher)
            .map_err(|_| KeyManagerStorageError::AeadError("Encryption Error".to_string()))?;
        Ok(key)
    }

    /// Commits a new key manager into the database
    pub async fn commit(&self, conn: &Connection) -> Result<(), KeyManagerStorageError> {
        let record = self.clone();
        conn.call(move |conn| {
            conn.execute(
                r#"
                    INSERT INTO imported_keys (wallet_id, private_key, public_key, timestamp)
                    VALUES (?, ?, ?, ?)
                    "#,
                params![
                    record.wallet_id,
                    record.private_key,
                    record.public_key,
                    record.timestamp
                ],
            )?;

            Ok(())
        })
        .await
        .map_err(|e| {
            KeyManagerStorageError::StorageError(format!(
                "Failed to save key manager imported key: {e}"
            ))
        })
    }
}

impl ImportedKeySql {
    fn row_to_state(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get::<_, i64>("id")? as i32,
            wallet_id: row.get::<_, i64>("wallet_id")? as u32,
            private_key: row.get("private_key")?,
            public_key: row.get("public_key")?,
            timestamp: row.get("timestamp")?,
        })
    }

    /// Retrieve every imported key currently in the database.
    /// Returns a `Vec` of [ImportedKeySql], if none are found, it will return an empty `Vec`.
    pub async fn index(
        conn: &Connection,
        wallet_id: u32,
    ) -> Result<Vec<Self>, KeyManagerStorageError> {
        conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT * FROM imported_keys WHERE wallet_id = ? ORDER BY timestamp DESC",
            )?;
            let rows = stmt.query_map(params![wallet_id as i64], Self::row_to_state)?;

            let mut keys = Vec::new();
            for row in rows {
                keys.push(row?);
            }

            Ok(keys)
        })
        .await
        .map_err(|e| {
            KeyManagerStorageError::StorageError(format!(
                "Failed to list key manager imported keys: {e}"
            ))
        })
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_imported_key(
        self,
        cipher: &XChaCha20Poly1305,
    ) -> Result<ImportedKey, KeyManagerStorageError> {
        let mut decrypted = self
            .decrypt(cipher)
            .map_err(|_| KeyManagerStorageError::AeadError("Decryption Error".to_string()))?;

        let imported_key = ImportedKey {
            private_key: PrivateKey::from_vec(&decrypted.private_key)?,
            public_key: CompressedPublicKey::from_hex(&decrypted.public_key)?,
        };
        decrypted.private_key.zeroize();
        Ok(imported_key)
    }

    /// Retrieve the key manager for the provided branch
    /// Will return Err if the branch does not exist in the database
    pub async fn get_key(
        key: &CompressedPublicKey,
        wallet_id: u32,
        conn: &Connection,
    ) -> Result<Self, KeyManagerStorageError> {
        let key_owned = key.to_hex();
        conn.call(move |conn| {
            let mut stmt =
                conn.prepare("SELECT * FROM imported_keys WHERE public_key = ? AND wallet_id = ?")?;
            let mut rows =
                stmt.query_map(params![key_owned, wallet_id as i64], Self::row_to_state)?;

            if let Some(row) = rows.next() {
                Ok(Some(row?))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| {
            KeyManagerStorageError::StorageError(format!(
                "Failed to get key manager imported key: {e}"
            ))
        })?
        .ok_or(KeyManagerStorageError::KeyManagerNotInitialized)
    }
}

impl Encryptable<XChaCha20Poly1305> for ImportedKeySql {
    fn domain(&self, field_name: &'static str) -> Vec<u8> {
        [
            DOMAIN,
            (self.wallet_id as u64).to_le_bytes().as_bytes(),
            field_name.as_bytes(),
        ]
        .concat()
        .to_vec()
    }

    fn encrypt(mut self, cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        self.private_key = encrypt_bytes_integral_nonce(
            cipher,
            self.domain("private_key"),
            Hidden::hide(self.private_key.clone()),
        )?;

        Ok(self)
    }

    fn decrypt(mut self, cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        self.private_key =
            decrypt_bytes_integral_nonce(cipher, self.domain("private_key"), &self.private_key)?;

        Ok(self)
    }
}

impl Encryptable<XChaCha20Poly1305> for NewImportedKeySql {
    fn domain(&self, field_name: &'static str) -> Vec<u8> {
        [
            DOMAIN,
            (self.wallet_id as u64).to_le_bytes().as_bytes(),
            field_name.as_bytes(),
        ]
        .concat()
        .to_vec()
    }

    fn encrypt(mut self, cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        self.private_key = encrypt_bytes_integral_nonce(
            cipher,
            self.domain("private_key"),
            Hidden::hide(self.private_key.clone()),
        )?;

        Ok(self)
    }

    fn decrypt(self, _cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        unimplemented!("Not supported")
    }
}
