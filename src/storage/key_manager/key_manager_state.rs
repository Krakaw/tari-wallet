use chacha20poly1305::XChaCha20Poly1305;
use chrono::{NaiveDateTime, Utc};
use rusqlite::{params, Row};
use tari_common_types::encryption::{
    decrypt_bytes_integral_nonce, encrypt_bytes_integral_nonce, Encryptable,
};
use tari_transaction_components::key_manager::{error::KeyManagerStorageError, KeyManagerState};
use tari_utilities::{ByteArray, Hidden};
use tokio_rusqlite::Connection;

const DOMAIN: &[u8; 11] = b"KEY_MANAGER";

#[derive(Clone, Debug)]
pub struct KeyManagerStateSql {
    pub id: i32,
    pub wallet_id: u32,
    pub branch_seed: String,
    pub primary_key_index: Vec<u8>,
    pub timestamp: NaiveDateTime,
}

/// Struct used to create a new Key manager in the database
#[derive(Clone, Debug)]
pub struct NewKeyManagerStateSql {
    pub wallet_id: u32,
    pub branch_seed: String,
    pub primary_key_index: Vec<u8>,
    pub timestamp: NaiveDateTime,
}

impl NewKeyManagerStateSql {
    pub fn new(km: KeyManagerState, wallet_id: u32) -> Self {
        Self {
            wallet_id,
            branch_seed: km.branch_seed,
            primary_key_index: km.primary_key_index.to_le_bytes().to_vec(),
            timestamp: Utc::now().naive_utc(),
        }
    }
}

impl TryFrom<KeyManagerStateSql> for KeyManagerState {
    type Error = KeyManagerStorageError;

    fn try_from(km: KeyManagerStateSql) -> Result<Self, Self::Error> {
        let mut bytes: [u8; 8] = [0u8; 8];
        bytes.copy_from_slice(&km.primary_key_index[..8]);
        Ok(Self {
            branch_seed: km.branch_seed,
            primary_key_index: u64::from_le_bytes(bytes),
        })
    }
}

impl NewKeyManagerStateSql {
    /// Commits a new key manager into the database
    pub async fn commit(&self, conn: &Connection) -> Result<(), KeyManagerStorageError> {
        let record = self.clone();
        conn.call(move |conn| {
            conn.execute(
                r#"
                    INSERT INTO key_manager_states (wallet_id, branch_seed, primary_key_index, timestamp)
                    VALUES (?, ?, ?, ?)
                    "#,
                params![
                    record.wallet_id,
                    record.branch_seed,
                    record.primary_key_index,
                    record.timestamp
                ],
            )?;

            Ok(())
        })
        .await
        .map_err(|e| {
            KeyManagerStorageError::StorageError(format!("Failed to save key manager state: {e}"))
        })
    }
}

impl KeyManagerStateSql {
    fn row_to_state(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get::<_, i64>("id")? as i32,
            wallet_id: row.get::<_, i64>("wallet_id")? as u32,
            branch_seed: row.get("branch_seed")?,
            primary_key_index: row.get::<_, Vec<u8>>("primary_key_index")?,
            timestamp: row.get("timestamp")?,
        })
    }

    /// Retrieve every key manager branch currently in the database.
    /// Returns a `Vec` of [KeyManagerStateSql], if none are found, it will return an empty `Vec`.
    pub async fn index(
        conn: &Connection,
        wallet_id: u32,
    ) -> Result<Vec<Self>, KeyManagerStorageError> {
        conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT * FROM key_manager_states WHERE wallet_id = ? ORDER BY timestamp DESC",
            )?;
            let rows = stmt.query_map(params![wallet_id as i64], Self::row_to_state)?;

            let mut statuses = Vec::new();
            for row in rows {
                statuses.push(row?);
            }

            Ok(statuses)
        })
        .await
        .map_err(|e| {
            KeyManagerStorageError::StorageError(format!("Failed to list key manager states: {e}"))
        })
    }

    /// Retrieve the key manager for the provided branch
    /// Will return Err if the branch does not exist in the database
    pub async fn get_state(
        branch: &str,
        wallet_id: u32,
        conn: &Connection,
    ) -> Result<Self, KeyManagerStorageError> {
        let branch_owned = branch.to_string();
        conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT * FROM key_manager_states WHERE branch_seed = ? AND wallet_id = ?",
            )?;
            let mut rows =
                stmt.query_map(params![branch_owned, wallet_id as i64], Self::row_to_state)?;

            if let Some(row) = rows.next() {
                Ok(Some(row?))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| {
            KeyManagerStorageError::StorageError(format!("Failed to get key manager state: {e}"))
        })?
        .ok_or(KeyManagerStorageError::KeyManagerNotInitialized)
    }

    /// Creates or updates the database with the key manager state in this instance.
    pub async fn set_state(&self, conn: &Connection) -> Result<(), KeyManagerStorageError> {
        let record = self.clone();
        match KeyManagerStateSql::get_state(&self.branch_seed, self.wallet_id, conn).await {
            Ok(km) => {
                let _ = conn
                    .call(move |conn| {
                        let rows_affected = conn.execute(
                            r#"
                        UPDATE key_manager_states
                        SET branch_seed = ?, primary_key_index = ?
                        WHERE id = ?
                        "#,
                            params![
                                record.branch_seed.clone(),
                                record.primary_key_index.clone(),
                                km.id as i64,
                            ],
                        )?;

                        if rows_affected == 0 {
                            Err(tokio_rusqlite::Error::Rusqlite(
                                rusqlite::Error::QueryReturnedNoRows,
                            ))
                        } else {
                            Ok(())
                        }
                    })
                    .await
                    .map_err(|e| {
                        KeyManagerStorageError::StorageError(format!(
                            "Failed to update key manager state: {e}"
                        ))
                    });
            }
            Err(_) => {
                let inserter = NewKeyManagerStateSql {
                    wallet_id: self.wallet_id,
                    branch_seed: self.branch_seed.clone(),
                    primary_key_index: self.primary_key_index.clone(),
                    timestamp: self.timestamp,
                };
                inserter.commit(conn).await?;
            }
        }
        Ok(())
    }

    /// Updates the key index of the of the provided key manager indicated by the id.
    pub async fn set_index(
        id: i32,
        index: Vec<u8>,
        conn: &Connection,
    ) -> Result<(), KeyManagerStorageError> {
        let rows_affected = conn
            .call(move |conn| {
                let rows_affected = conn.execute(
                    r#"
                        UPDATE key_manager_states
                        SET primary_key_index = ?
                        WHERE id = ?
                        "#,
                    params![index, id as i64,],
                )?;
                Ok(rows_affected)
            })
            .await
            .map_err(|e| {
                KeyManagerStorageError::StorageError(format!("Failed to save wallet: {e}"))
            })?;
        if rows_affected == 0 {
            return Err(KeyManagerStorageError::KeyManagerNotInitialized);
        }
        Ok(())
    }
}

impl Encryptable<XChaCha20Poly1305> for KeyManagerStateSql {
    fn domain(&self, field_name: &'static str) -> Vec<u8> {
        // Because there are two variable-length inputs in the concatenation, we prepend the length of the first
        [
            DOMAIN,
            (self.wallet_id as u64).to_le_bytes().as_bytes(),
            (self.branch_seed.len() as u64).to_le_bytes().as_bytes(),
            self.branch_seed.as_bytes(),
            field_name.as_bytes(),
        ]
        .concat()
        .to_vec()
    }

    fn encrypt(mut self, cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        self.primary_key_index = encrypt_bytes_integral_nonce(
            cipher,
            self.domain("primary_key_index"),
            Hidden::hide(self.primary_key_index.clone()),
        )?;

        Ok(self)
    }

    fn decrypt(mut self, cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        self.primary_key_index = decrypt_bytes_integral_nonce(
            cipher,
            self.domain("primary_key_index"),
            &self.primary_key_index,
        )?;

        Ok(self)
    }
}

impl Encryptable<XChaCha20Poly1305> for NewKeyManagerStateSql {
    fn domain(&self, field_name: &'static str) -> Vec<u8> {
        // Because there are two variable-length inputs in the concatenation, we prepend the length of the first
        [
            DOMAIN,
            (self.wallet_id as u64).to_le_bytes().as_bytes(),
            (self.branch_seed.len() as u64).to_le_bytes().as_bytes(),
            self.branch_seed.as_bytes(),
            field_name.as_bytes(),
        ]
        .concat()
        .to_vec()
    }

    fn encrypt(mut self, cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        self.primary_key_index = encrypt_bytes_integral_nonce(
            cipher,
            self.domain("primary_key_index"),
            Hidden::hide(self.primary_key_index.clone()),
        )?;

        Ok(self)
    }

    fn decrypt(self, _cipher: &XChaCha20Poly1305) -> Result<Self, String> {
        unimplemented!("Not supported")
    }
}
