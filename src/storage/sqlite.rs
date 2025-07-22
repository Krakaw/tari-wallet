//! SQLite storage implementation for wallet transactions
//!
//! This module provides a SQLite-based storage backend that implements the
//! `WalletStorage` trait for persisting wallet transaction data.

#[cfg(feature = "storage")]
use async_trait::async_trait;
#[cfg(feature = "storage")]
use rusqlite::{params, Row};
#[cfg(feature = "storage")]
use std::path::Path;
#[cfg(feature = "storage")]
use tokio_rusqlite::Connection;

#[cfg(feature = "storage")]
use crate::{
    data_structures::{
        payment_id::PaymentId,
        transaction::{TransactionDirection, TransactionStatus},
        types::CompressedCommitment,
        wallet_transaction::{WalletState, WalletTransaction},
    },
    errors::{LightweightWalletError, LightweightWalletResult},
    storage::{
        OutputFilter, OutputStatus, StorageStats, StoredOutput, StoredWallet, TransactionFilter,
        WalletStorage,
    },
};

/// SQLite storage backend for wallet transactions
#[cfg(feature = "storage")]
pub struct SqliteStorage {
    connection: Connection,
}

#[cfg(feature = "storage")]
impl SqliteStorage {
    /// Create a new SQLite storage instance
    pub async fn new<P: AsRef<Path>>(database_path: P) -> LightweightWalletResult<Self> {
        let connection = Connection::open(database_path).await.map_err(|e| {
            LightweightWalletError::StorageError(format!("Failed to open SQLite database: {e}"))
        })?;

        Ok(Self { connection })
    }

    /// Create an in-memory SQLite storage instance (useful for testing)
    pub async fn new_in_memory() -> LightweightWalletResult<Self> {
        let connection = Connection::open(":memory:").await.map_err(|e| {
            LightweightWalletError::StorageError(format!(
                "Failed to create in-memory database: {e}"
            ))
        })?;

        Ok(Self { connection })
    }

    /// Create the database schema
    async fn create_schema(&self) -> LightweightWalletResult<()> {
        let sql = r#"
            -- Wallets table
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                seed_phrase TEXT,
                view_key_hex TEXT NOT NULL,
                spend_key_hex TEXT,
                birthday_block INTEGER NOT NULL DEFAULT 0,
                latest_scanned_block INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- Wallet transactions table (updated with wallet_id foreign key)
            CREATE TABLE IF NOT EXISTS wallet_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_id INTEGER NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
                block_height INTEGER NOT NULL,
                output_index INTEGER,
                input_index INTEGER,
                commitment_hex TEXT NOT NULL,
                commitment_bytes BLOB NOT NULL,
                value INTEGER NOT NULL,
                payment_id_json TEXT NOT NULL,
                is_spent BOOLEAN NOT NULL DEFAULT FALSE,
                spent_in_block INTEGER,
                spent_in_input INTEGER,
                transaction_status INTEGER NOT NULL,
                transaction_direction INTEGER NOT NULL,
                is_mature BOOLEAN NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

                -- Unique constraint on wallet_id + commitment_hex + direction (allows both inbound and outbound for same commitment)
                UNIQUE(wallet_id, commitment_hex, transaction_direction)
            );

            -- UTXO Outputs table (NEW) for transaction creation
            CREATE TABLE IF NOT EXISTS outputs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_id INTEGER NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,

                -- Core UTXO identification
                commitment BLOB NOT NULL,
                hash BLOB NOT NULL,
                value BIGINT NOT NULL,

                -- Spending keys
                spending_key TEXT NOT NULL,
                script_private_key TEXT NOT NULL,

                -- Script and covenant data
                script BLOB NOT NULL,
                input_data BLOB NOT NULL,
                covenant BLOB NOT NULL,

                -- Output features and type
                output_type INTEGER NOT NULL,
                features_json TEXT NOT NULL,

                -- Maturity and lock constraints
                maturity BIGINT NOT NULL,
                script_lock_height BIGINT NOT NULL,

                -- Metadata signature components
                sender_offset_public_key BLOB NOT NULL,
                metadata_signature_ephemeral_commitment BLOB NOT NULL,
                metadata_signature_ephemeral_pubkey BLOB NOT NULL,
                metadata_signature_u_a BLOB NOT NULL,
                metadata_signature_u_x BLOB NOT NULL,
                metadata_signature_u_y BLOB NOT NULL,

                -- Payment information
                encrypted_data BLOB NOT NULL,
                minimum_value_promise BIGINT NOT NULL,

                -- Range proof
                rangeproof BLOB,

                -- Status and spending tracking
                status INTEGER NOT NULL DEFAULT 0,
                mined_height BIGINT,
                spent_in_tx_id BIGINT,

                -- Timestamps
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

                -- Constraints
                UNIQUE(wallet_id, commitment)
            );

            -- Indexes for wallets table
            CREATE INDEX IF NOT EXISTS idx_wallet_name ON wallets(name);
            CREATE INDEX IF NOT EXISTS idx_wallet_birthday ON wallets(birthday_block);

            -- Indexes for transactions table
            CREATE INDEX IF NOT EXISTS idx_transactions_wallet_id ON wallet_transactions(wallet_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_commitment_hex ON wallet_transactions(commitment_hex);
            CREATE INDEX IF NOT EXISTS idx_transactions_block_height ON wallet_transactions(block_height);
            CREATE INDEX IF NOT EXISTS idx_transactions_is_spent ON wallet_transactions(is_spent);
            CREATE INDEX IF NOT EXISTS idx_transactions_direction ON wallet_transactions(transaction_direction);
            CREATE INDEX IF NOT EXISTS idx_transactions_status ON wallet_transactions(transaction_status);
            CREATE INDEX IF NOT EXISTS idx_transactions_spent_block ON wallet_transactions(spent_in_block);
            CREATE INDEX IF NOT EXISTS idx_transactions_wallet_block ON wallet_transactions(wallet_id, block_height);
            -- Optimized compound index for spent marking query (commitment_hex + is_spent)
            CREATE INDEX IF NOT EXISTS idx_transactions_commitment_spent ON wallet_transactions(commitment_hex, is_spent);

            -- Indexes for outputs table (NEW)
            CREATE INDEX IF NOT EXISTS idx_outputs_wallet_id ON outputs(wallet_id);
            CREATE INDEX IF NOT EXISTS idx_outputs_commitment ON outputs(commitment);
            CREATE INDEX IF NOT EXISTS idx_outputs_status ON outputs(status);
            CREATE INDEX IF NOT EXISTS idx_outputs_value ON outputs(value);
            CREATE INDEX IF NOT EXISTS idx_outputs_maturity ON outputs(maturity);
            CREATE INDEX IF NOT EXISTS idx_outputs_mined_height ON outputs(mined_height);
            CREATE INDEX IF NOT EXISTS idx_outputs_spent_tx ON outputs(spent_in_tx_id);
            CREATE INDEX IF NOT EXISTS idx_outputs_wallet_status ON outputs(wallet_id, status);
            CREATE INDEX IF NOT EXISTS idx_outputs_spendable ON outputs(wallet_id, status, maturity, script_lock_height);

            -- Views for easy querying (NEW)
            CREATE VIEW IF NOT EXISTS spendable_outputs AS
            SELECT * FROM outputs
            WHERE status = 0  -- Unspent
              AND spent_in_tx_id IS NULL
              AND mined_height IS NOT NULL;

            -- Triggers to update updated_at timestamps
            CREATE TRIGGER IF NOT EXISTS update_wallets_timestamp
            AFTER UPDATE ON wallets
            BEGIN
                UPDATE wallets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;

            CREATE TRIGGER IF NOT EXISTS update_wallet_transactions_timestamp
            AFTER UPDATE ON wallet_transactions
            BEGIN
                UPDATE wallet_transactions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;

            CREATE TRIGGER IF NOT EXISTS update_outputs_timestamp
            AFTER UPDATE ON outputs
            BEGIN
                UPDATE outputs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
        "#;

        self.connection
            .call(move |conn| Ok(conn.execute_batch(sql)?))
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to create schema: {e}"))
            })?;

        Ok(())
    }

    /// Convert a database row to a StoredWallet
    fn row_to_wallet(row: &Row) -> rusqlite::Result<StoredWallet> {
        Ok(StoredWallet {
            id: Some(row.get::<_, i64>("id")? as u32),
            name: row.get("name")?,
            seed_phrase: row.get("seed_phrase")?,
            view_key_hex: row.get("view_key_hex")?,
            spend_key_hex: row.get("spend_key_hex")?,
            birthday_block: row.get::<_, i64>("birthday_block")? as u64,
            latest_scanned_block: row
                .get::<_, Option<i64>>("latest_scanned_block")?
                .map(|b| b as u64),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }

    /// Convert a database row to a WalletTransaction
    fn row_to_transaction(row: &Row) -> rusqlite::Result<WalletTransaction> {
        let commitment_bytes: Vec<u8> = row.get("commitment_bytes")?;
        let commitment_array: [u8; 32] = commitment_bytes.try_into().map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                0,
                "commitment_bytes".to_string(),
                rusqlite::types::Type::Blob,
            )
        })?;

        let payment_id_json: String = row.get("payment_id_json")?;
        let payment_id: PaymentId = serde_json::from_str(&payment_id_json)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let transaction_status_int: i32 = row.get("transaction_status")?;
        let transaction_status = TransactionStatus::try_from(transaction_status_int)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let transaction_direction_int: i32 = row.get("transaction_direction")?;
        let transaction_direction = TransactionDirection::try_from(transaction_direction_int)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        Ok(WalletTransaction {
            block_height: row.get::<_, i64>("block_height")? as u64,
            output_index: row
                .get::<_, Option<i64>>("output_index")?
                .map(|i| i as usize),
            input_index: row
                .get::<_, Option<i64>>("input_index")?
                .map(|i| i as usize),
            commitment: CompressedCommitment::new(commitment_array),
            output_hash: None, // Not stored in database, computed elsewhere when needed
            value: row.get::<_, i64>("value")? as u64,
            payment_id,
            is_spent: row.get("is_spent")?,
            spent_in_block: row
                .get::<_, Option<i64>>("spent_in_block")?
                .map(|i| i as u64),
            spent_in_input: row
                .get::<_, Option<i64>>("spent_in_input")?
                .map(|i| i as usize),
            transaction_status,
            transaction_direction,
            is_mature: row.get("is_mature")?,
        })
    }

    /// Convert a database row to a StoredOutput (NEW)
    fn row_to_output(row: &Row) -> rusqlite::Result<StoredOutput> {
        Ok(StoredOutput {
            id: Some(row.get::<_, i64>("id")? as u32),
            wallet_id: row.get::<_, i64>("wallet_id")? as u32,
            commitment: row.get("commitment")?,
            hash: row.get("hash")?,
            value: row.get::<_, i64>("value")? as u64,
            spending_key: row.get("spending_key")?,
            script_private_key: row.get("script_private_key")?,
            script: row.get("script")?,
            input_data: row.get("input_data")?,
            covenant: row.get("covenant")?,
            output_type: row.get::<_, i64>("output_type")? as u32,
            features_json: row.get("features_json")?,
            maturity: row.get::<_, i64>("maturity")? as u64,
            script_lock_height: row.get::<_, i64>("script_lock_height")? as u64,
            sender_offset_public_key: row.get("sender_offset_public_key")?,
            metadata_signature_ephemeral_commitment: row
                .get("metadata_signature_ephemeral_commitment")?,
            metadata_signature_ephemeral_pubkey: row.get("metadata_signature_ephemeral_pubkey")?,
            metadata_signature_u_a: row.get("metadata_signature_u_a")?,
            metadata_signature_u_x: row.get("metadata_signature_u_x")?,
            metadata_signature_u_y: row.get("metadata_signature_u_y")?,
            encrypted_data: row.get("encrypted_data")?,
            minimum_value_promise: row.get::<_, i64>("minimum_value_promise")? as u64,
            rangeproof: row.get("rangeproof")?,
            status: row.get::<_, i64>("status")? as u32,
            mined_height: row.get::<_, Option<i64>>("mined_height")?.map(|h| h as u64),
            spent_in_tx_id: row
                .get::<_, Option<i64>>("spent_in_tx_id")?
                .map(|id| id as u64),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }

    /// Build WHERE clause and parameters from filter
    fn build_filter_clause(
        filter: &TransactionFilter,
    ) -> (String, Vec<Box<dyn rusqlite::ToSql + Send>>) {
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();

        if let Some(wallet_id) = filter.wallet_id {
            conditions.push("wallet_id = ?".to_string());
            params.push(Box::new(wallet_id as i64));
        }

        if let Some((from, to)) = filter.block_height_range {
            conditions.push("block_height BETWEEN ? AND ?".to_string());
            params.push(Box::new(from as i64));
            params.push(Box::new(to as i64));
        }

        if let Some(direction) = filter.direction {
            conditions.push("transaction_direction = ?".to_string());
            params.push(Box::new(direction as i32));
        }

        if let Some(status) = filter.status {
            conditions.push("transaction_status = ?".to_string());
            params.push(Box::new(status as i32));
        }

        if let Some(is_spent) = filter.is_spent {
            conditions.push("is_spent = ?".to_string());
            params.push(Box::new(is_spent));
        }

        if let Some(is_mature) = filter.is_mature {
            conditions.push("is_mature = ?".to_string());
            params.push(Box::new(is_mature));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        (where_clause, params)
    }

    /// Build WHERE clause and parameters from output filter (NEW)
    fn build_output_filter_clause(
        filter: &OutputFilter,
    ) -> (String, Vec<Box<dyn rusqlite::ToSql + Send>>) {
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();

        if let Some(wallet_id) = filter.wallet_id {
            conditions.push("wallet_id = ?".to_string());
            params.push(Box::new(wallet_id as i64));
        }

        if let Some(status) = filter.status {
            conditions.push("status = ?".to_string());
            params.push(Box::new(status as u32 as i64));
        }

        if let Some(min_value) = filter.min_value {
            conditions.push("value >= ?".to_string());
            params.push(Box::new(min_value as i64));
        }

        if let Some(max_value) = filter.max_value {
            conditions.push("value <= ?".to_string());
            params.push(Box::new(max_value as i64));
        }

        if let Some((from, to)) = filter.maturity_range {
            conditions.push("maturity BETWEEN ? AND ?".to_string());
            params.push(Box::new(from as i64));
            params.push(Box::new(to as i64));
        }

        if let Some((from, to)) = filter.mined_height_range {
            conditions.push("mined_height BETWEEN ? AND ?".to_string());
            params.push(Box::new(from as i64));
            params.push(Box::new(to as i64));
        }

        if let Some(block_height) = filter.spendable_at_height {
            conditions.push("status = 0".to_string()); // Unspent
            conditions.push("spent_in_tx_id IS NULL".to_string());
            conditions.push("mined_height IS NOT NULL".to_string());
            conditions.push("? >= maturity".to_string());
            conditions.push("? >= script_lock_height".to_string());
            params.push(Box::new(block_height as i64));
            params.push(Box::new(block_height as i64));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        (where_clause, params)
    }
}

#[cfg(feature = "storage")]
#[async_trait]
impl WalletStorage for SqliteStorage {
    async fn initialize(&self) -> LightweightWalletResult<()> {
        self.create_schema().await
    }

    // === Wallet Management Methods ===

    async fn save_wallet(&self, wallet: &StoredWallet) -> LightweightWalletResult<u32> {
        // Validate wallet before saving
        wallet
            .validate()
            .map_err(|e| LightweightWalletError::StorageError(format!("Invalid wallet: {e}")))?;

        let wallet_clone = wallet.clone();
        self.connection.call(move |conn| {
            if let Some(wallet_id) = wallet_clone.id {
                // Update existing wallet
                let rows_affected = conn.execute(
                    r#"
                    UPDATE wallets
                    SET name = ?, seed_phrase = ?, view_key_hex = ?, spend_key_hex = ?, birthday_block = ?, latest_scanned_block = ?
                    WHERE id = ?
                    "#,
                    params![
                        wallet_clone.name,
                        wallet_clone.seed_phrase,
                        wallet_clone.view_key_hex,
                        wallet_clone.spend_key_hex,
                        wallet_clone.birthday_block as i64,
                        wallet_clone.latest_scanned_block.map(|b| b as i64),
                        wallet_id as i64,
                    ],
                )?;

                if rows_affected == 0 {
                    return Err(tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows));
                }
                Ok(wallet_id)
            } else {
                // Insert new wallet
                conn.execute(
                    r#"
                    INSERT INTO wallets (name, seed_phrase, view_key_hex, spend_key_hex, birthday_block, latest_scanned_block)
                    VALUES (?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        wallet_clone.name,
                        wallet_clone.seed_phrase,
                        wallet_clone.view_key_hex,
                        wallet_clone.spend_key_hex,
                        wallet_clone.birthday_block as i64,
                        wallet_clone.latest_scanned_block.map(|b| b as i64),
                    ],
                )?;

                Ok(conn.last_insert_rowid() as u32)
            }
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to save wallet: {e}")))
    }

    async fn get_wallet_by_id(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Option<StoredWallet>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT * FROM wallets WHERE id = ?")?;
                let mut rows = stmt.query_map(params![wallet_id as i64], Self::row_to_wallet)?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get wallet by ID: {e}"))
            })
    }

    async fn get_wallet_by_name(
        &self,
        name: &str,
    ) -> LightweightWalletResult<Option<StoredWallet>> {
        let name_owned = name.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT * FROM wallets WHERE name = ?")?;
                let mut rows = stmt.query_map(params![name_owned], Self::row_to_wallet)?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get wallet by name: {e}"))
            })
    }

    async fn list_wallets(&self) -> LightweightWalletResult<Vec<StoredWallet>> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT * FROM wallets ORDER BY created_at DESC")?;
                let rows = stmt.query_map([], Self::row_to_wallet)?;

                let mut wallets = Vec::new();
                for row in rows {
                    wallets.push(row?);
                }

                Ok(wallets)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to list wallets: {e}"))
            })
    }

    async fn delete_wallet(&self, wallet_id: u32) -> LightweightWalletResult<bool> {
        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;

                // Delete all transactions for this wallet (CASCADE should handle this, but explicit is safer)
                tx.execute(
                    "DELETE FROM wallet_transactions WHERE wallet_id = ?",
                    params![wallet_id as i64],
                )?;

                // Delete the wallet
                let rows_affected = tx.execute(
                    "DELETE FROM wallets WHERE id = ?",
                    params![wallet_id as i64],
                )?;

                tx.commit()?;
                Ok(rows_affected > 0)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to delete wallet: {e}"))
            })
    }

    async fn wallet_name_exists(&self, name: &str) -> LightweightWalletResult<bool> {
        let name_owned = name.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT 1 FROM wallets WHERE name = ? LIMIT 1")?;
                let exists = stmt.exists(params![name_owned])?;
                Ok(exists)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to check wallet name: {e}"))
            })
    }

    async fn update_wallet_scanned_block(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<()> {
        self.connection
            .call(move |conn| {
                let rows_affected = conn.execute(
                    "UPDATE wallets SET latest_scanned_block = ? WHERE id = ?",
                    params![block_height as i64, wallet_id as i64],
                )?;

                if rows_affected == 0 {
                    return Err(tokio_rusqlite::Error::Rusqlite(
                        rusqlite::Error::QueryReturnedNoRows,
                    ));
                }

                Ok(())
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to update wallet scanned block: {e}"
                ))
            })
    }

    // === Transaction Management Methods (updated with wallet support) ===

    async fn save_transaction(
        &self,
        wallet_id: u32,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()> {
        let tx = transaction.clone();
        self.connection.call(move |conn| {
            let payment_id_json = serde_json::to_string(&tx.payment_id)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            conn.execute(
                r#"
                INSERT OR REPLACE INTO wallet_transactions
                (wallet_id, block_height, output_index, input_index, commitment_hex, commitment_bytes,
                 value, payment_id_json, is_spent, spent_in_block, spent_in_input,
                 transaction_status, transaction_direction, is_mature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                params![
                    wallet_id as i64,
                    tx.block_height as i64,
                    tx.output_index.map(|i| i as i64),
                    tx.input_index.map(|i| i as i64),
                    tx.commitment_hex(),
                    tx.commitment.as_bytes().to_vec(),
                    tx.value as i64,
                    payment_id_json,
                    tx.is_spent,
                    tx.spent_in_block.map(|i| i as i64),
                    tx.spent_in_input.map(|i| i as i64),
                    tx.transaction_status as i32,
                    tx.transaction_direction as i32,
                    tx.is_mature,
                ],
            )?;
            Ok(())
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to save transaction: {e}")))?;

        Ok(())
    }

    async fn save_transactions(
        &self,
        wallet_id: u32,
        transactions: &[WalletTransaction],
    ) -> LightweightWalletResult<()> {
        let tx_list = transactions.to_vec();
        self.connection.call(move |conn| {
            let tx = conn.transaction()?;

            for transaction in &tx_list {
                let payment_id_json = serde_json::to_string(&transaction.payment_id)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

                tx.execute(
                    r#"
                    INSERT OR REPLACE INTO wallet_transactions
                    (wallet_id, block_height, output_index, input_index, commitment_hex, commitment_bytes,
                     value, payment_id_json, is_spent, spent_in_block, spent_in_input,
                     transaction_status, transaction_direction, is_mature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        wallet_id as i64,
                        transaction.block_height as i64,
                        transaction.output_index.map(|i| i as i64),
                        transaction.input_index.map(|i| i as i64),
                        transaction.commitment_hex(),
                        transaction.commitment.as_bytes().to_vec(),
                        transaction.value as i64,
                        payment_id_json,
                        transaction.is_spent,
                        transaction.spent_in_block.map(|i| i as i64),
                        transaction.spent_in_input.map(|i| i as i64),
                        transaction.transaction_status as i32,
                        transaction.transaction_direction as i32,
                        transaction.is_mature,
                    ],
                )?;
            }

            tx.commit()?;
            Ok(())
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to save transactions batch: {e}")))?;

        Ok(())
    }

    async fn update_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> LightweightWalletResult<()> {
        // For update, we need to find the wallet_id from the existing transaction
        let commitment_hex = transaction.commitment_hex();
        let tx_clone = transaction.clone();

        self.connection.call(move |conn| {
            // First get the wallet_id from existing transaction
            let mut stmt = conn.prepare("SELECT wallet_id FROM wallet_transactions WHERE commitment_hex = ? LIMIT 1")?;
            let wallet_id: i64 = stmt.query_row(params![commitment_hex], |row| row.get(0))?;

            // Now update the transaction
            let payment_id_json = serde_json::to_string(&tx_clone.payment_id)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            conn.execute(
                r#"
                UPDATE wallet_transactions
                SET block_height = ?, output_index = ?, input_index = ?, commitment_bytes = ?,
                    value = ?, payment_id_json = ?, is_spent = ?, spent_in_block = ?,
                    spent_in_input = ?, transaction_status = ?, transaction_direction = ?, is_mature = ?
                WHERE commitment_hex = ? AND wallet_id = ?
                "#,
                params![
                    tx_clone.block_height as i64,
                    tx_clone.output_index.map(|i| i as i64),
                    tx_clone.input_index.map(|i| i as i64),
                    tx_clone.commitment.as_bytes().to_vec(),
                    tx_clone.value as i64,
                    payment_id_json,
                    tx_clone.is_spent,
                    tx_clone.spent_in_block.map(|i| i as i64),
                    tx_clone.spent_in_input.map(|i| i as i64),
                    tx_clone.transaction_status as i32,
                    tx_clone.transaction_direction as i32,
                    tx_clone.is_mature,
                    commitment_hex,
                    wallet_id,
                ],
            )?;
            Ok(())
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to update transaction: {e}")))
    }

    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        spent_in_input: usize,
    ) -> LightweightWalletResult<bool> {
        let commitment_hex = commitment.to_hex();
        self.connection
            .call(move |conn| {
                let rows_affected = conn.execute(
                    r#"
                UPDATE wallet_transactions
                SET is_spent = TRUE, spent_in_block = ?, spent_in_input = ?
                WHERE commitment_hex = ? AND is_spent = FALSE
                "#,
                    params![spent_in_block as i64, spent_in_input as i64, commitment_hex],
                )?;
                Ok(rows_affected > 0)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to mark transaction spent: {e}"
                ))
            })
    }

    async fn mark_transactions_spent_batch(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> LightweightWalletResult<usize> {
        if spent_commitments.is_empty() {
            return Ok(0);
        }

        // Convert to owned data for the async call
        let batch_data: Vec<(String, i64, i64)> = spent_commitments
            .iter()
            .map(|(commitment, block_height, input_index)| {
                (
                    commitment.to_hex(),
                    *block_height as i64,
                    *input_index as i64,
                )
            })
            .collect();

        self.connection
            .call(move |conn| {
                let mut total_affected = 0;
                let tx = conn.transaction()?;

                // Use a prepared statement for better performance with large batches
                {
                    let mut stmt = tx.prepare(
                        r#"
                    UPDATE wallet_transactions
                    SET is_spent = TRUE, spent_in_block = ?, spent_in_input = ?
                    WHERE commitment_hex = ? AND is_spent = FALSE
                    "#,
                    )?;

                    for (commitment_hex, spent_in_block, spent_in_input) in batch_data {
                        let rows_affected =
                            stmt.execute(params![spent_in_block, spent_in_input, commitment_hex])?;
                        total_affected += rows_affected;
                    }
                } // stmt is dropped here, releasing the borrow

                tx.commit()?;
                Ok(total_affected)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to batch mark transactions spent: {e}"
                ))
            })
    }

    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<Option<WalletTransaction>> {
        let commitment_hex = commitment.to_hex();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT * FROM wallet_transactions WHERE commitment_hex = ? LIMIT 1",
                )?;

                let mut rows = stmt.query_map(params![commitment_hex], Self::row_to_transaction)?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to get transaction by commitment: {e}"
                ))
            })
    }

    async fn get_transactions(
        &self,
        filter: Option<TransactionFilter>,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        self.connection
            .call(move |conn| {
                let mut base_query = "SELECT * FROM wallet_transactions".to_string();
                let mut params_values: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();

                if let Some(ref filter) = filter {
                    let (where_clause, filter_params) = Self::build_filter_clause(filter);
                    if !where_clause.is_empty() {
                        base_query.push(' ');
                        base_query.push_str(&where_clause);
                        params_values.extend(filter_params);
                    }

                    base_query.push_str(" ORDER BY block_height ASC, id ASC");

                    if let Some(limit) = filter.limit {
                        base_query.push_str(&format!(" LIMIT {limit}"));
                    }

                    if let Some(offset) = filter.offset {
                        base_query.push_str(&format!(" OFFSET {offset}"));
                    }
                } else {
                    base_query.push_str(" ORDER BY block_height ASC, id ASC");
                }

                let mut stmt = conn.prepare(&base_query)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params_values
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::ToSql)
                    .collect();
                let rows = stmt.query_map(&param_refs[..], Self::row_to_transaction)?;

                let mut transactions = Vec::new();
                for row in rows {
                    transactions.push(row?);
                }

                Ok(transactions)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get transactions: {e}"))
            })
    }

    async fn load_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState> {
        let filter = TransactionFilter::new().with_wallet_id(wallet_id);
        let transactions = self.get_transactions(Some(filter)).await?;

        let mut wallet_state = WalletState::new();

        // Sort transactions by block height to ensure proper state building
        let mut sorted_transactions = transactions;
        sorted_transactions.sort_by_key(|tx| (tx.block_height, tx.output_index.unwrap_or(0)));

        // Rebuild wallet state from transactions
        for transaction in sorted_transactions {
            match transaction.transaction_direction {
                TransactionDirection::Inbound => {
                    wallet_state.add_received_output(
                        transaction.block_height,
                        transaction.output_index.unwrap_or(0),
                        transaction.commitment.clone(),
                        transaction.output_hash.clone(), // Include stored output hash
                        transaction.value,
                        transaction.payment_id.clone(),
                        transaction.transaction_status,
                        transaction.transaction_direction,
                        transaction.is_mature,
                    );

                    // If the transaction is spent, mark it as spent
                    if transaction.is_spent {
                        wallet_state.mark_output_spent(
                            &transaction.commitment,
                            transaction.spent_in_block.unwrap_or(0),
                            transaction.spent_in_input.unwrap_or(0),
                        );
                    }
                }
                TransactionDirection::Outbound => {
                    // Outbound transactions are typically created when marking as spent
                    // They should already be handled by the mark_output_spent logic above
                }
                TransactionDirection::Unknown => {
                    // Handle unknown transactions - add them to the list but don't affect balance
                    wallet_state.transactions.push(transaction);
                }
            }
        }

        Ok(wallet_state)
    }

    async fn get_statistics(&self) -> LightweightWalletResult<StorageStats> {
        self.get_wallet_statistics(None).await
    }

    /// Get statistics for a specific wallet, or global stats if wallet_id is None
    async fn get_wallet_statistics(
        &self,
        wallet_id: Option<u32>,
    ) -> LightweightWalletResult<StorageStats> {
        self.connection.call(move |conn| {
            let (query, params) = if let Some(wallet_id) = wallet_id {
                (r#"
                    SELECT
                        COUNT(*) as total_transactions,
                        COALESCE(SUM(CASE WHEN transaction_direction = 0 THEN 1 ELSE 0 END), 0) as inbound_count,
                        COALESCE(SUM(CASE WHEN transaction_direction = 1 THEN 1 ELSE 0 END), 0) as outbound_count,
                        COALESCE(SUM(CASE WHEN is_spent = FALSE AND transaction_direction = 0 THEN 1 ELSE 0 END), 0) as unspent_count,
                        COALESCE(SUM(CASE WHEN is_spent = TRUE AND transaction_direction = 0 THEN 1 ELSE 0 END), 0) as spent_count,
                        COALESCE(SUM(CASE WHEN transaction_direction = 0 THEN value ELSE 0 END), 0) as total_received,
                        COALESCE(SUM(CASE WHEN transaction_direction = 1 THEN value ELSE 0 END), 0) as total_spent,
                        MAX(block_height) as highest_block,
                        MIN(block_height) as lowest_block,
                        wallets.latest_scanned_block
                    FROM wallet_transactions
                    LEFT JOIN wallets ON wallet_transactions.wallet_id = wallets.id
                    WHERE wallet_id = ?
                "#, vec![wallet_id as i64])
            } else {
                (r#"
                    SELECT
                        COUNT(*) as total_transactions,
                        COALESCE(SUM(CASE WHEN transaction_direction = 0 THEN 1 ELSE 0 END), 0) as inbound_count,
                        COALESCE(SUM(CASE WHEN transaction_direction = 1 THEN 1 ELSE 0 END), 0) as outbound_count,
                        COALESCE(SUM(CASE WHEN is_spent = FALSE AND transaction_direction = 0 THEN 1 ELSE 0 END), 0) as unspent_count,
                        COALESCE(SUM(CASE WHEN is_spent = TRUE AND transaction_direction = 0 THEN 1 ELSE 0 END), 0) as spent_count,
                        COALESCE(SUM(CASE WHEN transaction_direction = 0 THEN value ELSE 0 END), 0) as total_received,
                        COALESCE(SUM(CASE WHEN transaction_direction = 1 THEN value ELSE 0 END), 0) as total_spent,
                        MAX(block_height) as highest_block,
                        MIN(block_height) as lowest_block,
                        wallets.latest_scanned_block
                    FROM wallet_transactions
                    LEFT JOIN wallets ON wallet_transactions.wallet_id = wallets.id
                "#, vec![])
            };

            let mut stmt = conn.prepare(query)?;
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter()
                .map(|p| p as &dyn rusqlite::ToSql)
                .collect();

            let row = stmt.query_row(&param_refs[..], |row| {
                let total_received: i64 = row.get("total_received")?;
                let total_spent: i64 = row.get("total_spent")?;

                Ok(StorageStats {
                    total_transactions: row.get::<_, i64>("total_transactions")? as usize,
                    inbound_count: row.get::<_, i64>("inbound_count")? as usize,
                    outbound_count: row.get::<_, i64>("outbound_count")? as usize,
                    unspent_count: row.get::<_, i64>("unspent_count")? as usize,
                    spent_count: row.get::<_, i64>("spent_count")? as usize,
                    total_received: total_received as u64,
                    total_spent: total_spent as u64,
                    current_balance: (total_received - total_spent),
                    highest_block: row.get::<_, Option<i64>>("highest_block")?.map(|h| h as u64),
                    lowest_block: row.get::<_, Option<i64>>("lowest_block")?.map(|h| h as u64),
                    latest_scanned_block: row.get::<_, Option<i64>>("latest_scanned_block")?.map(|h| h as u64),
                })
            })?;

            Ok(row)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to get statistics: {e}")))
    }

    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new().with_block_range(from_block, to_block);
        self.get_transactions(Some(filter)).await
    }

    async fn get_unspent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new()
            .with_spent_status(false)
            .with_direction(TransactionDirection::Inbound);
        self.get_transactions(Some(filter)).await
    }

    async fn get_spent_transactions(&self) -> LightweightWalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new()
            .with_spent_status(true)
            .with_direction(TransactionDirection::Inbound);
        self.get_transactions(Some(filter)).await
    }

    async fn has_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> LightweightWalletResult<bool> {
        let commitment_hex = commitment.to_hex();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT 1 FROM wallet_transactions WHERE commitment_hex = ? LIMIT 1",
                )?;
                let exists = stmt.exists(params![commitment_hex])?;
                Ok(exists)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to check commitment existence: {e}"
                ))
            })
    }

    async fn get_highest_block(&self) -> LightweightWalletResult<Option<u64>> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT MAX(block_height) FROM wallet_transactions")?;
                let block_height: Option<i64> = stmt.query_row([], |row| row.get(0))?;
                Ok(block_height.map(|h| h as u64))
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get highest block: {e}"))
            })
    }

    async fn get_lowest_block(&self) -> LightweightWalletResult<Option<u64>> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT MIN(block_height) FROM wallet_transactions")?;
                let block_height: Option<i64> = stmt.query_row([], |row| row.get(0))?;
                Ok(block_height.map(|h| h as u64))
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get lowest block: {e}"))
            })
    }

    async fn clear_all_transactions(&self) -> LightweightWalletResult<()> {
        self.connection
            .call(|conn| {
                conn.execute("DELETE FROM wallet_transactions", [])?;
                Ok(())
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to clear transactions: {e}"))
            })?;
        self.connection
            .call(|conn| {
                conn.execute("DELETE FROM outputs", [])?;
                Ok(())
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to clear outputs: {e}"))
            })?;
        Ok(())
    }

    async fn get_transaction_count(&self) -> LightweightWalletResult<usize> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT COUNT(*) FROM wallet_transactions")?;
                let count: i64 = stmt.query_row([], |row| row.get(0))?;
                Ok(count as usize)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to get transaction count: {e}"
                ))
            })
    }

    // === UTXO Output Management Methods (NEW) ===

    async fn save_output(&self, output: &StoredOutput) -> LightweightWalletResult<u32> {
        let output_clone = output.clone();
        self.connection.call(move |conn| {
            if let Some(output_id) = output_clone.id {
                // Update existing output
                let rows_affected = conn.execute(
                    r#"
                    UPDATE outputs
                    SET wallet_id = ?, commitment = ?, hash = ?, value = ?, spending_key = ?,
                        script_private_key = ?, script = ?, input_data = ?, covenant = ?,
                        output_type = ?, features_json = ?, maturity = ?, script_lock_height = ?,
                        sender_offset_public_key = ?, metadata_signature_ephemeral_commitment = ?,
                        metadata_signature_ephemeral_pubkey = ?, metadata_signature_u_a = ?,
                        metadata_signature_u_x = ?, metadata_signature_u_y = ?, encrypted_data = ?,
                        minimum_value_promise = ?, rangeproof = ?, status = ?, mined_height = ?,
                        spent_in_tx_id = ?
                    WHERE id = ?
                    "#,
                    params![
                        output_clone.wallet_id as i64,
                        output_clone.commitment,
                        output_clone.hash,
                        output_clone.value as i64,
                        output_clone.spending_key,
                        output_clone.script_private_key,
                        output_clone.script,
                        output_clone.input_data,
                        output_clone.covenant,
                        output_clone.output_type as i64,
                        output_clone.features_json,
                        output_clone.maturity as i64,
                        output_clone.script_lock_height as i64,
                        output_clone.sender_offset_public_key,
                        output_clone.metadata_signature_ephemeral_commitment,
                        output_clone.metadata_signature_ephemeral_pubkey,
                        output_clone.metadata_signature_u_a,
                        output_clone.metadata_signature_u_x,
                        output_clone.metadata_signature_u_y,
                        output_clone.encrypted_data,
                        output_clone.minimum_value_promise as i64,
                        output_clone.rangeproof,
                        output_clone.status as i64,
                        output_clone.mined_height.map(|h| h as i64),
                        output_clone.spent_in_tx_id.map(|id| id as i64),
                        output_id as i64,
                    ],
                )?;

                if rows_affected == 0 {
                    return Err(tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows));
                }
                Ok(output_id)
            } else {
                // Insert new output (ignore if already exists due to unique constraint)
                conn.execute(
                    r#"
                    INSERT OR IGNORE INTO outputs
                    (wallet_id, commitment, hash, value, spending_key, script_private_key,
                     script, input_data, covenant, output_type, features_json, maturity,
                     script_lock_height, sender_offset_public_key, metadata_signature_ephemeral_commitment,
                     metadata_signature_ephemeral_pubkey, metadata_signature_u_a, metadata_signature_u_x,
                     metadata_signature_u_y, encrypted_data, minimum_value_promise, rangeproof,
                     status, mined_height, spent_in_tx_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        output_clone.wallet_id as i64,
                        output_clone.commitment,
                        output_clone.hash,
                        output_clone.value as i64,
                        output_clone.spending_key,
                        output_clone.script_private_key,
                        output_clone.script,
                        output_clone.input_data,
                        output_clone.covenant,
                        output_clone.output_type as i64,
                        output_clone.features_json,
                        output_clone.maturity as i64,
                        output_clone.script_lock_height as i64,
                        output_clone.sender_offset_public_key,
                        output_clone.metadata_signature_ephemeral_commitment,
                        output_clone.metadata_signature_ephemeral_pubkey,
                        output_clone.metadata_signature_u_a,
                        output_clone.metadata_signature_u_x,
                        output_clone.metadata_signature_u_y,
                        output_clone.encrypted_data,
                        output_clone.minimum_value_promise as i64,
                        output_clone.rangeproof,
                        output_clone.status as i64,
                        output_clone.mined_height.map(|h| h as i64),
                        output_clone.spent_in_tx_id.map(|id| id as i64),
                    ],
                )?;

                Ok(conn.last_insert_rowid() as u32)
            }
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to save output: {e}")))
    }

    async fn save_outputs(&self, outputs: &[StoredOutput]) -> LightweightWalletResult<Vec<u32>> {
        let outputs_clone = outputs.to_vec();
        self.connection.call(move |conn| {
            let tx = conn.transaction()?;
            let mut output_ids = Vec::new();

            for output in &outputs_clone {
                if let Some(output_id) = output.id {
                    // Update existing
                    let rows_affected = tx.execute(
                        r#"
                        UPDATE outputs
                        SET wallet_id = ?, commitment = ?, hash = ?, value = ?, spending_key = ?,
                            script_private_key = ?, script = ?, input_data = ?, covenant = ?,
                            output_type = ?, features_json = ?, maturity = ?, script_lock_height = ?,
                            sender_offset_public_key = ?, metadata_signature_ephemeral_commitment = ?,
                            metadata_signature_ephemeral_pubkey = ?, metadata_signature_u_a = ?,
                            metadata_signature_u_x = ?, metadata_signature_u_y = ?, encrypted_data = ?,
                            minimum_value_promise = ?, rangeproof = ?, status = ?, mined_height = ?,
                            spent_in_tx_id = ?
                        WHERE id = ?
                        "#,
                        params![
                            output.wallet_id as i64,
                            output.commitment,
                            output.hash,
                            output.value as i64,
                            output.spending_key,
                            output.script_private_key,
                            output.script,
                            output.input_data,
                            output.covenant,
                            output.output_type as i64,
                            output.features_json,
                            output.maturity as i64,
                            output.script_lock_height as i64,
                            output.sender_offset_public_key,
                            output.metadata_signature_ephemeral_commitment,
                            output.metadata_signature_ephemeral_pubkey,
                            output.metadata_signature_u_a,
                            output.metadata_signature_u_x,
                            output.metadata_signature_u_y,
                            output.encrypted_data,
                            output.minimum_value_promise as i64,
                            output.rangeproof,
                            output.status as i64,
                            output.mined_height.map(|h| h as i64),
                            output.spent_in_tx_id.map(|id| id as i64),
                            output_id as i64,
                        ],
                    )?;

                    if rows_affected > 0 {
                        output_ids.push(output_id);
                    }
                } else {
                    // Insert new (ignore if already exists due to unique constraint)
                    tx.execute(
                        r#"
                        INSERT OR IGNORE INTO outputs
                        (wallet_id, commitment, hash, value, spending_key, script_private_key,
                         script, input_data, covenant, output_type, features_json, maturity,
                         script_lock_height, sender_offset_public_key, metadata_signature_ephemeral_commitment,
                         metadata_signature_ephemeral_pubkey, metadata_signature_u_a, metadata_signature_u_x,
                         metadata_signature_u_y, encrypted_data, minimum_value_promise, rangeproof,
                         status, mined_height, spent_in_tx_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                        params![
                            output.wallet_id as i64,
                            output.commitment,
                            output.hash,
                            output.value as i64,
                            output.spending_key,
                            output.script_private_key,
                            output.script,
                            output.input_data,
                            output.covenant,
                            output.output_type as i64,
                            output.features_json,
                            output.maturity as i64,
                            output.script_lock_height as i64,
                            output.sender_offset_public_key,
                            output.metadata_signature_ephemeral_commitment,
                            output.metadata_signature_ephemeral_pubkey,
                            output.metadata_signature_u_a,
                            output.metadata_signature_u_x,
                            output.metadata_signature_u_y,
                            output.encrypted_data,
                            output.minimum_value_promise as i64,
                            output.rangeproof,
                            output.status as i64,
                            output.mined_height.map(|h| h as i64),
                            output.spent_in_tx_id.map(|id| id as i64),
                        ],
                    )?;

                    output_ids.push(tx.last_insert_rowid() as u32);
                }
            }

            tx.commit()?;
            Ok(output_ids)
        }).await.map_err(|e| LightweightWalletError::StorageError(format!("Failed to save outputs: {e}")))
    }

    async fn update_output(&self, output: &StoredOutput) -> LightweightWalletResult<()> {
        let output_id = output.id.ok_or_else(|| {
            LightweightWalletError::StorageError("Output must have an ID to update".to_string())
        })?;

        let output_clone = output.clone();
        self.connection
            .call(move |conn| {
                let rows_affected = conn.execute(
                    r#"
                UPDATE outputs
                SET wallet_id = ?, commitment = ?, hash = ?, value = ?, spending_key = ?,
                    script_private_key = ?, script = ?, input_data = ?, covenant = ?,
                    output_type = ?, features_json = ?, maturity = ?, script_lock_height = ?,
                    sender_offset_public_key = ?, metadata_signature_ephemeral_commitment = ?,
                    metadata_signature_ephemeral_pubkey = ?, metadata_signature_u_a = ?,
                    metadata_signature_u_x = ?, metadata_signature_u_y = ?, encrypted_data = ?,
                    minimum_value_promise = ?, rangeproof = ?, status = ?, mined_height = ?,
                    spent_in_tx_id = ?
                WHERE id = ?
                "#,
                    params![
                        output_clone.wallet_id as i64,
                        output_clone.commitment,
                        output_clone.hash,
                        output_clone.value as i64,
                        output_clone.spending_key,
                        output_clone.script_private_key,
                        output_clone.script,
                        output_clone.input_data,
                        output_clone.covenant,
                        output_clone.output_type as i64,
                        output_clone.features_json,
                        output_clone.maturity as i64,
                        output_clone.script_lock_height as i64,
                        output_clone.sender_offset_public_key,
                        output_clone.metadata_signature_ephemeral_commitment,
                        output_clone.metadata_signature_ephemeral_pubkey,
                        output_clone.metadata_signature_u_a,
                        output_clone.metadata_signature_u_x,
                        output_clone.metadata_signature_u_y,
                        output_clone.encrypted_data,
                        output_clone.minimum_value_promise as i64,
                        output_clone.rangeproof,
                        output_clone.status as i64,
                        output_clone.mined_height.map(|h| h as i64),
                        output_clone.spent_in_tx_id.map(|id| id as i64),
                        output_id as i64,
                    ],
                )?;

                if rows_affected == 0 {
                    return Err(tokio_rusqlite::Error::Rusqlite(
                        rusqlite::Error::QueryReturnedNoRows,
                    ));
                }

                Ok(())
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to update output: {e}"))
            })
    }

    async fn mark_output_spent(
        &self,
        output_id: u32,
        spent_in_tx_id: u64,
    ) -> LightweightWalletResult<()> {
        self.connection
            .call(move |conn| {
                let rows_affected = conn.execute(
                    "UPDATE outputs SET status = 1, spent_in_tx_id = ? WHERE id = ?",
                    params![spent_in_tx_id as i64, output_id as i64],
                )?;

                if rows_affected == 0 {
                    return Err(tokio_rusqlite::Error::Rusqlite(
                        rusqlite::Error::QueryReturnedNoRows,
                    ));
                }

                Ok(())
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to mark output spent: {e}"))
            })
    }

    async fn get_output_by_id(
        &self,
        output_id: u32,
    ) -> LightweightWalletResult<Option<StoredOutput>> {
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT * FROM outputs WHERE id = ?")?;
                let mut rows = stmt.query_map(params![output_id as i64], Self::row_to_output)?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get output by ID: {e}"))
            })
    }

    async fn get_output_by_commitment(
        &self,
        commitment: &[u8],
    ) -> LightweightWalletResult<Option<StoredOutput>> {
        let commitment_vec = commitment.to_vec();
        self.connection
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT * FROM outputs WHERE commitment = ? LIMIT 1")?;
                let mut rows = stmt.query_map(params![commitment_vec], Self::row_to_output)?;

                if let Some(row) = rows.next() {
                    Ok(Some(row?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to get output by commitment: {e}"
                ))
            })
    }

    async fn get_outputs(
        &self,
        filter: Option<OutputFilter>,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        self.connection
            .call(move |conn| {
                let mut base_query = "SELECT * FROM outputs".to_string();
                let mut params_values: Vec<Box<dyn rusqlite::ToSql + Send>> = Vec::new();

                if let Some(ref filter) = filter {
                    let (where_clause, filter_params) = Self::build_output_filter_clause(filter);
                    if !where_clause.is_empty() {
                        base_query.push(' ');
                        base_query.push_str(&where_clause);
                        params_values.extend(filter_params);
                    }

                    base_query.push_str(" ORDER BY created_at ASC");

                    if let Some(limit) = filter.limit {
                        base_query.push_str(&format!(" LIMIT {limit}"));
                    }

                    if let Some(offset) = filter.offset {
                        base_query.push_str(&format!(" OFFSET {offset}"));
                    }
                } else {
                    base_query.push_str(" ORDER BY created_at ASC");
                }

                let mut stmt = conn.prepare(&base_query)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params_values
                    .iter()
                    .map(|p| p.as_ref() as &dyn rusqlite::ToSql)
                    .collect();
                let rows = stmt.query_map(&param_refs[..], Self::row_to_output)?;

                let mut outputs = Vec::new();
                for row in rows {
                    outputs.push(row?);
                }

                Ok(outputs)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get outputs: {e}"))
            })
    }

    async fn get_unspent_outputs(
        &self,
        wallet_id: u32,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let filter = OutputFilter::new()
            .with_wallet_id(wallet_id)
            .with_status(OutputStatus::Unspent);
        self.get_outputs(Some(filter)).await
    }

    async fn get_spendable_outputs(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let filter = OutputFilter::new()
            .with_wallet_id(wallet_id)
            .spendable_at(block_height);
        self.get_outputs(Some(filter)).await
    }

    async fn get_spendable_balance(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> LightweightWalletResult<u64> {
        self.connection
            .call(move |conn| {
                let balance: i64 = conn.query_row(
                    r#"
                SELECT COALESCE(SUM(value), 0) FROM outputs
                WHERE wallet_id = ?
                  AND status = 0
                  AND spent_in_tx_id IS NULL
                  AND mined_height IS NOT NULL
                  AND ? >= maturity
                  AND ? >= script_lock_height
                "#,
                    params![wallet_id as i64, block_height as i64, block_height as i64],
                    |row| row.get(0),
                )?;
                Ok(balance as u64)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!(
                    "Failed to get spendable balance: {e}"
                ))
            })
    }

    async fn delete_output(&self, output_id: u32) -> LightweightWalletResult<bool> {
        self.connection
            .call(move |conn| {
                let rows_affected = conn.execute(
                    "DELETE FROM outputs WHERE id = ?",
                    params![output_id as i64],
                )?;
                Ok(rows_affected > 0)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to delete output: {e}"))
            })
    }

    async fn clear_outputs(&self, wallet_id: u32) -> LightweightWalletResult<()> {
        self.connection
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM outputs WHERE wallet_id = ?",
                    params![wallet_id as i64],
                )?;
                Ok(())
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to clear outputs: {e}"))
            })
    }

    async fn get_output_count(&self, wallet_id: u32) -> LightweightWalletResult<usize> {
        self.connection
            .call(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM outputs WHERE wallet_id = ?",
                    params![wallet_id as i64],
                    |row| row.get(0),
                )?;
                Ok(count as usize)
            })
            .await
            .map_err(|e| {
                LightweightWalletError::StorageError(format!("Failed to get output count: {e}"))
            })
    }

    async fn close(&self) -> LightweightWalletResult<()> {
        // tokio-rusqlite automatically handles connection cleanup on drop
        Ok(())
    }
}

#[cfg(not(feature = "storage"))]
/// Placeholder for when storage feature is not enabled
pub struct SqliteStorage;

#[cfg(not(feature = "storage"))]
impl SqliteStorage {
    pub async fn new<P>(_database_path: P) -> Result<Self, &'static str> {
        Err("Storage feature not enabled")
    }

    pub async fn new_in_memory() -> Result<Self, &'static str> {
        Err("Storage feature not enabled")
    }
}

#[cfg(feature = "storage")]
#[cfg(test)]
mod storage_tests {
    use super::super::*;
    use crate::data_structures::{
        payment_id::PaymentId,
        transaction::{TransactionDirection, TransactionStatus},
        types::CompressedCommitment,
        wallet_transaction::WalletTransaction,
    };

    #[tokio::test]
    async fn test_sqlite_storage_initialization() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Test that we can get stats from empty storage
        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.current_balance, 0);
        assert_eq!(stats.highest_block, None);
        assert_eq!(stats.lowest_block, None);
    }

    #[tokio::test]
    async fn test_save_and_retrieve_transaction() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let commitment = CompressedCommitment::new([1u8; 32]);
        let transaction = WalletTransaction::new(
            12345,
            Some(0),
            None,
            commitment.clone(),
            None,
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        // Save transaction
        storage.save_transaction(0, &transaction).await.unwrap();

        // Retrieve by commitment
        let retrieved = storage
            .get_transaction_by_commitment(&commitment)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved_tx = retrieved.unwrap();
        assert_eq!(retrieved_tx.block_height, 12345);
        assert_eq!(retrieved_tx.value, 1000000);
        assert_eq!(retrieved_tx.commitment, commitment);

        // Test existence check
        assert!(storage.has_commitment(&commitment).await.unwrap());
    }

    #[tokio::test]
    async fn test_batch_save_transactions() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let transactions = vec![
            WalletTransaction::new(
                100,
                Some(0),
                None,
                CompressedCommitment::new([1u8; 32]),
                None,
                1000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true,
            ),
            WalletTransaction::new(
                200,
                Some(1),
                None,
                CompressedCommitment::new([2u8; 32]),
                None,
                2000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true,
            ),
            WalletTransaction::new(
                300,
                None,
                Some(0),
                CompressedCommitment::new([1u8; 32]),
                None,
                1000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Outbound,
                true,
            ),
        ];

        storage.save_transactions(0, &transactions).await.unwrap();

        let all_transactions = storage.get_transactions(None).await.unwrap();
        assert_eq!(all_transactions.len(), 3);

        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 3);
        assert_eq!(stats.inbound_count, 2);
        assert_eq!(stats.outbound_count, 1);
    }

    #[tokio::test]
    async fn test_mark_transaction_spent() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let commitment = CompressedCommitment::new([1u8; 32]);
        let transaction = WalletTransaction::new(
            100,
            Some(0),
            None,
            commitment.clone(),
            None,
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        storage.save_transaction(0, &transaction).await.unwrap();

        // Mark as spent
        let marked = storage
            .mark_transaction_spent(&commitment, 200, 5)
            .await
            .unwrap();
        assert!(marked);

        // Retrieve and verify spent status
        let updated_tx = storage
            .get_transaction_by_commitment(&commitment)
            .await
            .unwrap()
            .unwrap();
        assert!(updated_tx.is_spent);
        assert_eq!(updated_tx.spent_in_block, Some(200));
        assert_eq!(updated_tx.spent_in_input, Some(5));

        // Try to mark again (should return false since already spent)
        let marked_again = storage
            .mark_transaction_spent(&commitment, 300, 10)
            .await
            .unwrap();
        assert!(!marked_again);
    }

    #[tokio::test]
    async fn test_filtered_queries() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Add test transactions
        let transactions = vec![
            WalletTransaction::new(
                100,
                Some(0),
                None,
                CompressedCommitment::new([1u8; 32]),
                None,
                1000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true,
            ),
            WalletTransaction::new(
                200,
                Some(1),
                None,
                CompressedCommitment::new([2u8; 32]),
                None,
                2000000,
                PaymentId::Empty,
                TransactionStatus::CoinbaseConfirmed,
                TransactionDirection::Inbound,
                true,
            ),
            WalletTransaction::new(
                300,
                None,
                Some(0),
                CompressedCommitment::new([1u8; 32]),
                None,
                1000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Outbound,
                true,
            ),
        ];

        storage.save_transactions(0, &transactions).await.unwrap();

        // Test filter by direction
        let inbound_filter = TransactionFilter::new().with_direction(TransactionDirection::Inbound);
        let inbound_txs = storage
            .get_transactions(Some(inbound_filter))
            .await
            .unwrap();
        assert_eq!(inbound_txs.len(), 2);

        // Test filter by block range
        let block_filter = TransactionFilter::new().with_block_range(150, 250);
        let block_txs = storage.get_transactions(Some(block_filter)).await.unwrap();
        assert_eq!(block_txs.len(), 1);
        assert_eq!(block_txs[0].block_height, 200);

        // Test filter by status
        let coinbase_filter =
            TransactionFilter::new().with_status(TransactionStatus::CoinbaseConfirmed);
        let coinbase_txs = storage
            .get_transactions(Some(coinbase_filter))
            .await
            .unwrap();
        assert_eq!(coinbase_txs.len(), 1);
        assert_eq!(
            coinbase_txs[0].transaction_status,
            TransactionStatus::CoinbaseConfirmed
        );

        // Test limit
        let limited_filter = TransactionFilter::new().with_limit(2);
        let limited_txs = storage
            .get_transactions(Some(limited_filter))
            .await
            .unwrap();
        assert_eq!(limited_txs.len(), 2);
    }

    #[tokio::test]
    async fn test_wallet_state_reconstruction() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let commitment1 = CompressedCommitment::new([1u8; 32]);
        let commitment2 = CompressedCommitment::new([2u8; 32]);

        // Add inbound transactions
        let inbound_tx1 = WalletTransaction::new(
            100,
            Some(0),
            None,
            commitment1.clone(),
            None,
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );
        let inbound_tx2 = WalletTransaction::new(
            200,
            Some(1),
            None,
            commitment2.clone(),
            None,
            2000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        storage.save_transaction(0, &inbound_tx1).await.unwrap();
        storage.save_transaction(0, &inbound_tx2).await.unwrap();

        // Mark one as spent
        storage
            .mark_transaction_spent(&commitment1, 300, 0)
            .await
            .unwrap();

        // Load wallet state
        let wallet_state = storage.load_wallet_state(0).await.unwrap();

        // Verify the state
        let (total_received, total_spent, balance, unspent_count, spent_count) =
            wallet_state.get_summary();
        assert_eq!(total_received, 3000000); // 1M + 2M
        assert_eq!(total_spent, 1000000); // 1M spent
        assert_eq!(balance, 2000000); // 2M remaining
        assert_eq!(unspent_count, 1); // 1 unspent
        assert_eq!(spent_count, 1); // 1 spent

        let unspent = wallet_state.get_unspent_transactions();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].commitment, commitment2);

        let spent = wallet_state.get_spent_transactions();
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0].commitment, commitment1);
    }

    #[tokio::test]
    async fn test_block_range_queries() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Add transactions across different blocks
        let transactions = vec![
            WalletTransaction::new(
                100,
                Some(0),
                None,
                CompressedCommitment::new([1u8; 32]),
                None,
                1000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true,
            ),
            WalletTransaction::new(
                500,
                Some(1),
                None,
                CompressedCommitment::new([2u8; 32]),
                None,
                2000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true,
            ),
            WalletTransaction::new(
                1000,
                Some(2),
                None,
                CompressedCommitment::new([3u8; 32]),
                None,
                3000000,
                PaymentId::Empty,
                TransactionStatus::MinedConfirmed,
                TransactionDirection::Inbound,
                true,
            ),
        ];

        storage.save_transactions(0, &transactions).await.unwrap();

        // Test block range queries
        let range_txs = storage
            .get_transactions_by_block_range(200, 800)
            .await
            .unwrap();
        assert_eq!(range_txs.len(), 1);
        assert_eq!(range_txs[0].block_height, 500);

        // Test highest/lowest block
        let highest = storage.get_highest_block().await.unwrap();
        let lowest = storage.get_lowest_block().await.unwrap();
        assert_eq!(highest, Some(1000));
        assert_eq!(lowest, Some(100));
    }

    #[tokio::test]
    async fn test_clear_all_transactions() {
        let storage = SqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        // Add some transactions
        let transaction = WalletTransaction::new(
            100,
            Some(0),
            None,
            CompressedCommitment::new([1u8; 32]),
            None,
            1000000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );
        storage.save_transaction(0, &transaction).await.unwrap();

        // Verify they exist
        let count = storage.get_transaction_count().await.unwrap();
        assert_eq!(count, 1);

        // Clear all
        storage.clear_all_transactions().await.unwrap();

        // Verify they're gone
        let count = storage.get_transaction_count().await.unwrap();
        assert_eq!(count, 0);

        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.total_transactions, 0);
    }
}
