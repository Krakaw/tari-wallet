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
    errors::{WalletError, WalletResult},
    storage::{
        OutputFilter, OutputStatus, SqlitePerformanceConfig, StorageStats, StoredOutput,
        StoredWallet, TransactionFilter, WalletStorage,
    },
};

/// SQLite storage backend for wallet transactions with configurable batching
#[cfg(feature = "storage")]
pub struct SqliteStorage {
    connection: Connection,
    performance_config: SqlitePerformanceConfig,
    batch_size: usize,
}

#[cfg(feature = "storage")]
impl SqliteStorage {
    /// Create a new SQLite storage instance with default batch size (1000)
    pub async fn new<P: AsRef<Path>>(database_path: P) -> WalletResult<Self> {
        Self::new_with_config(
            database_path,
            SqlitePerformanceConfig::production_optimized(),
            1000,
        )
        .await
    }

    /// Create a new SQLite storage instance with custom performance configuration and batch size
    /// Set batch_size to 1 for immediate writes (no batching)
    pub async fn new_with_config<P: AsRef<Path>>(
        database_path: P,
        performance_config: SqlitePerformanceConfig,
        batch_size: usize,
    ) -> WalletResult<Self> {
        let connection = Connection::open(database_path).await.map_err(|e| {
            WalletError::StorageError(format!("Failed to open SQLite database: {e}"))
        })?;

        let storage = Self {
            connection,
            performance_config,
            batch_size: batch_size.max(1), // Ensure at least 1
        };

        // Apply performance optimizations before any other operations
        storage
            .performance_config
            .apply_to_connection(&storage.connection)
            .await?;

        Ok(storage)
    }

    /// Create an in-memory SQLite storage instance (useful for testing) with default batch size (1000)
    pub async fn new_in_memory() -> WalletResult<Self> {
        Self::new_in_memory_with_config(SqlitePerformanceConfig::ultra_fast(), 1000).await
    }

    /// Create an in-memory SQLite storage instance with custom performance configuration and batch size
    pub async fn new_in_memory_with_config(
        performance_config: SqlitePerformanceConfig,
        batch_size: usize,
    ) -> WalletResult<Self> {
        let connection = Connection::open(":memory:").await.map_err(|e| {
            WalletError::StorageError(format!("Failed to create in-memory database: {e}"))
        })?;

        let storage = Self {
            connection,
            performance_config,
            batch_size: batch_size.max(1), // Ensure at least 1
        };

        // Apply performance optimizations
        storage
            .performance_config
            .apply_to_connection(&storage.connection)
            .await?;

        Ok(storage)
    }

    /// Create the database schema
    async fn create_schema(&self) -> WalletResult<()> {
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
                block_hash TEXT,
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

            -- Simple wallet events table for audit logging
            CREATE TABLE IF NOT EXISTS wallet_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- Index for efficient querying
            CREATE INDEX IF NOT EXISTS idx_events_wallet_id ON wallet_events(wallet_id);
            CREATE INDEX IF NOT EXISTS idx_events_type ON wallet_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON wallet_events(timestamp);
        "#;

        self.connection
            .call(move |conn| Ok(conn.execute_batch(sql)?))
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to create schema: {e}")))?;

        // Apply scanning-specific optimizations after schema creation
        self.performance_config
            .apply_scanning_optimizations(&self.connection)
            .await?;

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
            block_hash: row.get("block_hash")?,
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
    async fn initialize(&self) -> WalletResult<()> {
        self.create_schema().await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // === Wallet Management Methods ===

    async fn save_wallet(&self, wallet: &StoredWallet) -> WalletResult<u32> {
        // Validate wallet before saving
        wallet
            .validate()
            .map_err(|e| WalletError::StorageError(format!("Invalid wallet: {e}")))?;

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
        }).await.map_err(|e| WalletError::StorageError(format!("Failed to save wallet: {e}")))
    }

    async fn get_wallet_by_id(&self, wallet_id: u32) -> WalletResult<Option<StoredWallet>> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to get wallet by ID: {e}")))
    }

    async fn get_wallet_by_name(&self, name: &str) -> WalletResult<Option<StoredWallet>> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to get wallet by name: {e}")))
    }

    async fn list_wallets(&self) -> WalletResult<Vec<StoredWallet>> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to list wallets: {e}")))
    }

    async fn delete_wallet(&self, wallet_id: u32) -> WalletResult<bool> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to delete wallet: {e}")))
    }

    async fn wallet_name_exists(&self, name: &str) -> WalletResult<bool> {
        let name_owned = name.to_string();
        self.connection
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT 1 FROM wallets WHERE name = ? LIMIT 1")?;
                let exists = stmt.exists(params![name_owned])?;
                Ok(exists)
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to check wallet name: {e}")))
    }

    async fn update_wallet_scanned_block(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> WalletResult<()> {
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
                WalletError::StorageError(format!("Failed to update wallet scanned block: {e}"))
            })
    }

    // === Transaction Management Methods (updated with wallet support) ===

    async fn save_transaction(
        &self,
        wallet_id: u32,
        transaction: &WalletTransaction,
    ) -> WalletResult<()> {
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
        }).await.map_err(|e| WalletError::StorageError(format!("Failed to save transaction: {e}")))?;

        Ok(())
    }

    async fn save_transactions(
        &self,
        wallet_id: u32,
        transactions: &[WalletTransaction],
    ) -> WalletResult<()> {
        if transactions.is_empty() {
            return Ok(());
        }

        // Always use batched approach for multiple transactions - it's more efficient
        // even when batch_size=1 because we can put multiple transactions in one DB transaction

        // Use batched approach for better performance
        let tx_list = transactions.to_vec();
        self.connection.call(move |conn| {
            let tx = conn.transaction()?;

            {
                // Use prepared statement for better performance
                let mut stmt = tx.prepare_cached(
                    r#"
                    INSERT OR REPLACE INTO wallet_transactions
                    (wallet_id, block_height, output_index, input_index, commitment_hex, commitment_bytes,
                     value, payment_id_json, is_spent, spent_in_block, spent_in_input,
                     transaction_status, transaction_direction, is_mature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )?;

                for transaction in &tx_list {
                    let payment_id_json = serde_json::to_string(&transaction.payment_id)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

                    stmt.execute(params![
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
                    ])?;
                }
            } // stmt is dropped here

            tx.commit()?;
            Ok(())
        }).await.map_err(|e| WalletError::StorageError(format!("Failed to save transactions batch: {e}")))?;

        Ok(())
    }

    async fn update_transaction(&self, transaction: &WalletTransaction) -> WalletResult<()> {
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
        }).await.map_err(|e| WalletError::StorageError(format!("Failed to update transaction: {e}")))
    }

    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        spent_in_input: usize,
    ) -> WalletResult<bool> {
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
                WalletError::StorageError(format!("Failed to mark transaction spent: {e}"))
            })
    }

    async fn mark_transactions_spent_batch(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> WalletResult<usize> {
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
                WalletError::StorageError(format!("Failed to batch mark transactions spent: {e}"))
            })
    }

    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> WalletResult<Option<WalletTransaction>> {
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
                WalletError::StorageError(format!("Failed to get transaction by commitment: {e}"))
            })
    }

    async fn get_transactions(
        &self,
        filter: Option<TransactionFilter>,
    ) -> WalletResult<Vec<WalletTransaction>> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to get transactions: {e}")))
    }

    async fn load_wallet_state(&self, wallet_id: u32) -> WalletResult<WalletState> {
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

    async fn get_statistics(&self) -> WalletResult<StorageStats> {
        self.get_wallet_statistics(None).await
    }

    /// Get statistics for a specific wallet, or global stats if wallet_id is None
    async fn get_wallet_statistics(&self, wallet_id: Option<u32>) -> WalletResult<StorageStats> {
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
        }).await.map_err(|e| WalletError::StorageError(format!("Failed to get statistics: {e}")))
    }

    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> WalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new().with_block_range(from_block, to_block);
        self.get_transactions(Some(filter)).await
    }

    async fn mark_spent_outputs_from_inputs(
        &self,
        wallet_id: u32,
        from_block: u64,
        to_block: u64,
    ) -> WalletResult<usize> {
        self.connection
            .call(move |conn| {
                let mut spent_count = 0;
                // Now we properly match blockchain inputs (stored during scanning) against our outputs
                // 
                // During scanning we store:
                // - Our outputs as transaction_direction = 0 (Inbound)
                // - All blockchain inputs as transaction_direction = 1 (Outbound)
                //
                // This allows us to find when our outputs have been spent by matching commitments
                let mut stmt = conn.prepare(
                    r#"
                    UPDATE wallet_transactions AS outputs
                    SET is_spent = TRUE,
                        spent_in_block = inputs.block_height,
                        spent_in_input = inputs.input_index,
                        updated_at = CURRENT_TIMESTAMP
                    FROM wallet_transactions AS inputs
                    WHERE outputs.wallet_id = ?
                    AND outputs.transaction_direction = 0  -- Our received outputs
                    AND outputs.is_spent = FALSE
                    AND inputs.wallet_id = ?
                    AND inputs.transaction_direction = 1  -- Blockchain inputs
                    AND inputs.block_height BETWEEN ? AND ?
                    AND inputs.input_index IS NOT NULL    -- Ensure this is actually an input record
                    AND outputs.commitment_hex = inputs.commitment_hex  -- Match commitments
                    "#,
                )?;

                spent_count += stmt.execute(params![
                    wallet_id,    // wallet_id for outputs
                    wallet_id,    // wallet_id for inputs
                    from_block,   // from_block for input search
                    to_block      // to_block for input search
                ])?;

                // Also update the outputs table for consistency
                let mut output_stmt = conn.prepare(
                    r#"
                    UPDATE outputs 
                    SET status = 1,
                        spent_in_tx_id = (
                            SELECT inputs.block_height
                            FROM wallet_transactions AS inputs
                            WHERE inputs.wallet_id = ?
                            AND inputs.transaction_direction = 1
                            AND inputs.block_height BETWEEN ? AND ?
                            AND inputs.commitment_bytes = outputs.commitment
                            LIMIT 1
                        ),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE wallet_id = ?
                    AND status = 0
                    AND commitment IN (
                        SELECT DISTINCT outputs.commitment_bytes
                        FROM wallet_transactions AS outputs
                        INNER JOIN wallet_transactions AS inputs ON (
                            outputs.commitment_hex = inputs.commitment_hex
                            AND outputs.wallet_id = inputs.wallet_id
                            AND outputs.transaction_direction = 0
                            AND inputs.transaction_direction = 1
                            AND inputs.block_height BETWEEN ? AND ?
                        )
                        WHERE outputs.wallet_id = ?
                        AND outputs.is_spent = TRUE
                        AND outputs.updated_at >= datetime('now', '-1 minute')  -- Recently marked as spent
                    )
                    "#,
                )?;

                output_stmt.execute(params![
                    wallet_id,    // wallet_id for subquery input search
                    from_block,   // from_block for subquery
                    to_block,     // to_block for subquery
                    wallet_id,    // wallet_id for outputs table
                    from_block,   // from_block for inner join
                    to_block,     // to_block for inner join
                    wallet_id     // wallet_id for inner join
                ])?;

                Ok(spent_count)
            })
            .await
            .map_err(|e| {
                WalletError::StorageError(format!(
                    "Failed to mark spent outputs from inputs: {e}"
                ))
            })
    }

    async fn get_unspent_transactions(&self) -> WalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new()
            .with_spent_status(false)
            .with_direction(TransactionDirection::Inbound);
        self.get_transactions(Some(filter)).await
    }

    async fn get_spent_transactions(&self) -> WalletResult<Vec<WalletTransaction>> {
        let filter = TransactionFilter::new()
            .with_spent_status(true)
            .with_direction(TransactionDirection::Inbound);
        self.get_transactions(Some(filter)).await
    }

    async fn has_commitment(&self, commitment: &CompressedCommitment) -> WalletResult<bool> {
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
                WalletError::StorageError(format!("Failed to check commitment existence: {e}"))
            })
    }

    async fn get_highest_block(&self) -> WalletResult<Option<u64>> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT MAX(block_height) FROM wallet_transactions")?;
                let block_height: Option<i64> = stmt.query_row([], |row| row.get(0))?;
                Ok(block_height.map(|h| h as u64))
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to get highest block: {e}")))
    }

    async fn get_lowest_block(&self) -> WalletResult<Option<u64>> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT MIN(block_height) FROM wallet_transactions")?;
                let block_height: Option<i64> = stmt.query_row([], |row| row.get(0))?;
                Ok(block_height.map(|h| h as u64))
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to get lowest block: {e}")))
    }

    async fn clear_all_transactions(&self) -> WalletResult<()> {
        self.connection
            .call(|conn| {
                conn.execute("DELETE FROM wallet_transactions", [])?;
                Ok(())
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to clear transactions: {e}")))?;
        self.connection
            .call(|conn| {
                conn.execute("DELETE FROM outputs", [])?;
                Ok(())
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to clear outputs: {e}")))?;
        self.connection
            .call(|conn| {
                conn.execute("UPDATE wallets SET latest_scanned_block = 0", [])?;
                Ok(())
            })
            .await
            .map_err(|e| {
                WalletError::StorageError(format!("Failed to clear latest scanned block: {e}"))
            })?;
        Ok(())
    }

    async fn get_transaction_count(&self) -> WalletResult<usize> {
        self.connection
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT COUNT(*) FROM wallet_transactions")?;
                let count: i64 = stmt.query_row([], |row| row.get(0))?;
                Ok(count as usize)
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to get transaction count: {e}")))
    }

    // === UTXO Output Management Methods (NEW) ===

    async fn save_output(&self, output: &StoredOutput) -> WalletResult<u32> {
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
                    block_hash = ?, spent_in_tx_id = ?
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
                        output_clone.block_hash,
                        output_clone.spent_in_tx_id.map(|id| id as i64),
                         output_id as i64,
                    ],
                )?;

                if rows_affected == 0 {
                    return Err(tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows));
                }
                Ok(output_id)
            } else {
                // Insert new output
                conn.execute(
                    r#"
                    INSERT INTO outputs
                    (wallet_id, commitment, hash, value, spending_key, script_private_key,
                    script, input_data, covenant, output_type, features_json, maturity,
                    script_lock_height, sender_offset_public_key, metadata_signature_ephemeral_commitment,
                    metadata_signature_ephemeral_pubkey, metadata_signature_u_a, metadata_signature_u_x,
                    metadata_signature_u_y, encrypted_data, minimum_value_promise, rangeproof,
                    status, mined_height, block_hash, spent_in_tx_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        output_clone.block_hash,
                            output_clone.spent_in_tx_id.map(|id| id as i64),
                     ],
                )?;

                Ok(conn.last_insert_rowid() as u32)
            }
        }).await.map_err(|e| WalletError::StorageError(format!("Failed to save output: {e}")))
    }

    async fn save_outputs(&self, outputs: &[StoredOutput]) -> WalletResult<Vec<u32>> {
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
                    // Insert new with ON CONFLICT handling to update existing outputs
                    tx.execute(
                        r#"
                        INSERT INTO outputs
                        (wallet_id, commitment, hash, value, spending_key, script_private_key,
                         script, input_data, covenant, output_type, features_json, maturity,
                         script_lock_height, sender_offset_public_key, metadata_signature_ephemeral_commitment,
                         metadata_signature_ephemeral_pubkey, metadata_signature_u_a, metadata_signature_u_x,
                         metadata_signature_u_y, encrypted_data, minimum_value_promise, rangeproof,
                         status, mined_height, block_hash, spent_in_tx_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(wallet_id, commitment) DO UPDATE SET
                            status = EXCLUDED.status,
                            mined_height = COALESCE(EXCLUDED.mined_height, mined_height),
                            spent_in_tx_id = COALESCE(EXCLUDED.spent_in_tx_id, spent_in_tx_id),
                            updated_at = CURRENT_TIMESTAMP
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
                            output.block_hash,
                            output.spent_in_tx_id.map(|id| id as i64),
                        ],
                    )?;

                    // Get the row ID (either newly inserted or existing)
                    let row_id = if tx.changes() > 0 {
                        // New insert
                        tx.last_insert_rowid() as u32
                    } else {
                        // Conflict occurred, get existing ID
                        let mut stmt = tx.prepare("SELECT id FROM outputs WHERE wallet_id = ? AND commitment = ?")?;
                        let existing_id: i64 = stmt.query_row(params![output.wallet_id as i64, output.commitment], |row| {
                            row.get(0)
                        })?;
                        existing_id as u32
                    };
                    output_ids.push(row_id);
                }
            }

            tx.commit()?;
            Ok(output_ids)
        }).await.map_err(|e| WalletError::StorageError(format!("Failed to save outputs: {e}")))
    }

    async fn update_output(&self, output: &StoredOutput) -> WalletResult<()> {
        let output_id = output.id.ok_or_else(|| {
            WalletError::StorageError("Output must have an ID to update".to_string())
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
            .map_err(|e| WalletError::StorageError(format!("Failed to update output: {e}")))
    }

    async fn mark_output_spent(&self, output_id: u32, spent_in_tx_id: u64) -> WalletResult<()> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to mark output spent: {e}")))
    }

    async fn get_output_by_id(&self, output_id: u32) -> WalletResult<Option<StoredOutput>> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to get output by ID: {e}")))
    }

    async fn get_output_by_commitment(
        &self,
        commitment: &[u8],
    ) -> WalletResult<Option<StoredOutput>> {
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
                WalletError::StorageError(format!("Failed to get output by commitment: {e}"))
            })
    }

    async fn get_outputs(&self, filter: Option<OutputFilter>) -> WalletResult<Vec<StoredOutput>> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to get outputs: {e}")))
    }

    async fn get_unspent_outputs(&self, wallet_id: u32) -> WalletResult<Vec<StoredOutput>> {
        let filter = OutputFilter::new()
            .with_wallet_id(wallet_id)
            .with_status(OutputStatus::Unspent);
        self.get_outputs(Some(filter)).await
    }

    async fn get_spendable_outputs(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> WalletResult<Vec<StoredOutput>> {
        let filter = OutputFilter::new()
            .with_wallet_id(wallet_id)
            .spendable_at(block_height);
        self.get_outputs(Some(filter)).await
    }

    async fn get_spendable_balance(&self, wallet_id: u32, block_height: u64) -> WalletResult<u64> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to get spendable balance: {e}")))
    }

    async fn delete_output(&self, output_id: u32) -> WalletResult<bool> {
        self.connection
            .call(move |conn| {
                let rows_affected = conn.execute(
                    "DELETE FROM outputs WHERE id = ?",
                    params![output_id as i64],
                )?;
                Ok(rows_affected > 0)
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to delete output: {e}")))
    }

    async fn clear_outputs(&self, wallet_id: u32) -> WalletResult<()> {
        self.connection
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM outputs WHERE wallet_id = ?",
                    params![wallet_id as i64],
                )?;
                Ok(())
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to clear outputs: {e}")))
    }

    async fn get_output_count(&self, wallet_id: u32) -> WalletResult<usize> {
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
            .map_err(|e| WalletError::StorageError(format!("Failed to get output count: {e}")))
    }

    async fn store_simple_event(
        &self,
        wallet_id: u32,
        event_type: &str,
        event_data: &str,
    ) -> WalletResult<()> {
        let wallet_id = wallet_id as i64;
        let event_type = event_type.to_string();
        let event_data = event_data.to_string();

        self.connection
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO wallet_events (wallet_id, event_type, event_data) VALUES (?, ?, ?)",
                    params![wallet_id, event_type, event_data],
                )?;
                Ok(())
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to store event: {e}")))
    }

    async fn close(&self) -> WalletResult<()> {
        // tokio-rusqlite automatically handles connection cleanup on drop
        Ok(())
    }
}

#[cfg(feature = "storage")]
impl SqliteStorage {
    /// Save multiple batches of transactions in a single large transaction
    /// This is the high-performance method for bulk operations
    pub async fn save_all_batches(
        &self,
        batches: &[(u32, Vec<WalletTransaction>)], // (wallet_id, transactions)
    ) -> WalletResult<()> {
        if batches.is_empty() {
            return Ok(());
        }

        let batches_owned = batches.to_vec();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    // Prepare the statement once for all operations
                    let mut stmt = tx.prepare_cached(
                        r#"
                        INSERT OR REPLACE INTO wallet_transactions
                        (wallet_id, block_height, output_index, input_index, commitment_hex, commitment_bytes,
                         value, payment_id_json, is_spent, spent_in_block, spent_in_input,
                         transaction_status, transaction_direction, is_mature)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                    )?;

                    for (wallet_id, transactions) in batches_owned {
                        for transaction in transactions {
                            let payment_id_json = serde_json::to_string(&transaction.payment_id)
                                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

                            stmt.execute(params![
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
                            ])?;
                        }
                    }
                } // stmt is dropped here

                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to save all batches: {e}")))
    }

    /// Save multiple batches of outputs in a single large transaction
    pub async fn save_all_output_batches(
        &self,
        batches: &[(u32, Vec<StoredOutput>)], // (wallet_id, outputs)
    ) -> WalletResult<()> {
        if batches.is_empty() {
            return Ok(());
        }

        let batches_owned = batches.to_vec();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare_cached(
                        r#"
                        INSERT OR REPLACE INTO outputs
                        (wallet_id, commitment, hash, value, spending_key, script_private_key,
                         script, input_data, covenant, output_type, features_json, maturity,
                         script_lock_height, sender_offset_public_key, metadata_signature_ephemeral_commitment,
                         metadata_signature_ephemeral_pubkey, metadata_signature_u_a, metadata_signature_u_x,
                         metadata_signature_u_y, encrypted_data, minimum_value_promise, rangeproof,
                         status, mined_height, block_hash, spent_in_tx_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                    )?;

                    for (wallet_id, outputs) in batches_owned {
                        for output in outputs {
                            stmt.execute(params![
                                wallet_id as i64,
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
                                output.block_hash,
                                output.spent_in_tx_id.map(|id| id as i64),
                            ])?;
                        }
                    }
                } // stmt is dropped here

                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to save all output batches: {e}")))
    }

    /// Mark multiple batches of transactions as spent in a single large transaction
    pub async fn mark_all_spent_batches(
        &self,
        batches: &[Vec<(CompressedCommitment, u64, usize)>], // Multiple batches of (commitment, block, input_index)
    ) -> WalletResult<usize> {
        if batches.is_empty() {
            return Ok(0);
        }

        // Flatten all batches into a single vector
        let all_spent: Vec<(String, i64, i64)> = batches
            .iter()
            .flat_map(|batch| {
                batch.iter().map(|(commitment, block_height, input_index)| {
                    (
                        commitment.to_hex(),
                        *block_height as i64,
                        *input_index as i64,
                    )
                })
            })
            .collect();

        if all_spent.is_empty() {
            return Ok(0);
        }

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                let mut total_affected = 0;

                {
                    let mut stmt = tx.prepare_cached(
                        r#"
                        UPDATE wallet_transactions
                        SET is_spent = TRUE, spent_in_block = ?, spent_in_input = ?
                        WHERE commitment_hex = ? AND is_spent = FALSE
                        "#,
                    )?;

                    for (commitment_hex, spent_in_block, spent_in_input) in all_spent {
                        let rows_affected =
                            stmt.execute(params![spent_in_block, spent_in_input, commitment_hex])?;
                        total_affected += rows_affected;
                    }
                } // stmt is dropped here

                tx.commit()?;
                Ok(total_affected)
            })
            .await
            .map_err(|e| {
                WalletError::StorageError(format!("Failed to mark all spent batches: {e}"))
            })
    }

    /// Update wallet scanned blocks for multiple wallets in a single transaction
    pub async fn update_all_wallet_scanned_blocks(
        &self,
        updates: &[(u32, u64)], // (wallet_id, block_height)
    ) -> WalletResult<()> {
        if updates.is_empty() {
            return Ok(());
        }

        let updates_owned = updates.to_vec();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare_cached(
                        "UPDATE wallets SET latest_scanned_block = ? WHERE id = ?",
                    )?;

                    for (wallet_id, block_height) in updates_owned {
                        stmt.execute(params![block_height as i64, wallet_id as i64])?;
                    }
                } // stmt is dropped here

                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|e| {
                WalletError::StorageError(format!(
                    "Failed to update all wallet scanned blocks: {e}"
                ))
            })
    }

    /// Get the configured batch size
    pub fn batch_size(&self) -> usize {
        self.batch_size
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
