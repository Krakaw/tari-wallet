//! Enhanced SQLite storage with improved batch transaction performance
//!
//! This module provides an enhanced version of the SQLite storage that uses
//! a single large transaction for all batch operations, dramatically improving
//! performance for high-throughput scanning operations.

#[cfg(feature = "storage")]
use crate::{
    data_structures::{types::CompressedCommitment, wallet_transaction::WalletTransaction},
    errors::{WalletError, WalletResult},
    storage::{sqlite::SqliteStorage, StoredOutput, WalletStorage},
};
#[cfg(feature = "storage")]
use async_trait::async_trait;
#[cfg(feature = "storage")]
use std::path::Path;
#[cfg(feature = "storage")]
use tokio_rusqlite::Connection;

/// Enhanced SQLite storage with better batch performance
#[cfg(feature = "storage")]
pub struct EnhancedSqliteStorage {
    /// Underlying SQLite storage
    base_storage: SqliteStorage,
    /// Direct connection for custom batch operations
    connection: Connection,
}

#[cfg(feature = "storage")]
impl EnhancedSqliteStorage {
    /// Create a new enhanced SQLite storage instance
    pub async fn new<P: AsRef<Path>>(database_path: P) -> WalletResult<Self> {
        let base_storage = SqliteStorage::new(&database_path).await?;
        let connection = Connection::open(&database_path).await.map_err(|e| {
            WalletError::StorageError(format!("Failed to open enhanced connection: {e}"))
        })?;

        Ok(Self {
            base_storage,
            connection,
        })
    }

    /// Create an in-memory enhanced SQLite storage instance
    pub async fn new_in_memory() -> WalletResult<Self> {
        let base_storage = SqliteStorage::new_in_memory().await?;
        let connection = Connection::open(":memory:").await.map_err(|e| {
            WalletError::StorageError(format!(
                "Failed to create in-memory enhanced connection: {e}"
            ))
        })?;

        Ok(Self {
            base_storage,
            connection,
        })
    }

    /// Save multiple batches of transactions in a single large transaction
    pub async fn save_all_batches(
        &self,
        batches: &[(u32, Vec<WalletTransaction>)], // (wallet_id, transactions)
    ) -> WalletResult<()> {
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

                            stmt.execute(rusqlite::params![
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
            .map_err(|e| WalletError::StorageError(format!("Failed to save all batches: {e}")))?;

        Ok(())
    }

    /// Save multiple batches of outputs in a single large transaction
    pub async fn save_all_output_batches(
        &self,
        output_batches: &[Vec<StoredOutput>],
    ) -> WalletResult<Vec<u32>> {
        let batches_owned = output_batches.to_vec();
        let mut total_outputs = 0;
        for batch in &batches_owned {
            total_outputs += batch.len();
        }

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    // Prepare the statement once for all operations
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

                for batch in batches_owned {
                    for output in batch {
                        stmt.execute(rusqlite::params![
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
                        ])?;
                    }
                }
                } // stmt is dropped here

                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|e| WalletError::StorageError(format!("Failed to save all output batches: {e}")))?;

        // Return sequential IDs for compatibility
        Ok((0..total_outputs).map(|i| i as u32).collect())
    }

    /// Mark multiple transaction batches as spent in a single large transaction
    pub async fn mark_all_spent_batches(
        &self,
        spent_batches: &[Vec<(CompressedCommitment, u64, usize)>],
    ) -> WalletResult<usize> {
        let batches_owned = spent_batches.to_vec();
        let mut _total_commitments = 0;
        for batch in &batches_owned {
            _total_commitments += batch.len();
        }

        let marked_count = self
            .connection
            .call(move |conn| {
                let tx = conn.transaction()?;
                let mut total_affected = 0;

                {
                    // Prepare the statement once for all operations
                    let mut stmt = tx.prepare_cached(
                        r#"
                    UPDATE wallet_transactions
                    SET is_spent = TRUE, spent_in_block = ?, spent_in_input = ?
                    WHERE commitment_hex = ? AND is_spent = FALSE
                    "#,
                    )?;

                    for batch in batches_owned {
                        for (commitment, block_height, input_index) in batch {
                            let rows_affected = stmt.execute(rusqlite::params![
                                block_height as i64,
                                input_index as i64,
                                commitment.to_hex(),
                            ])?;
                            total_affected += rows_affected;
                        }
                    }
                } // stmt is dropped here

                tx.commit()?;
                Ok(total_affected)
            })
            .await
            .map_err(|e| {
                WalletError::StorageError(format!("Failed to mark all spent batches: {e}"))
            })?;

        Ok(marked_count)
    }

    /// Update multiple wallet scanned blocks in a single transaction
    pub async fn update_all_wallet_scanned_blocks(
        &self,
        updates: &[(u32, u64)], // (wallet_id, block_height)
    ) -> WalletResult<()> {
        let updates_owned = updates.to_vec();

        self.connection
            .call(move |conn| {
                let tx = conn.transaction()?;

                for (wallet_id, block_height) in updates_owned {
                    let rows_affected = tx.execute(
                        "UPDATE wallets SET latest_scanned_block = ? WHERE id = ?",
                        rusqlite::params![block_height as i64, wallet_id as i64],
                    )?;

                    if rows_affected == 0 {
                        return Err(tokio_rusqlite::Error::Rusqlite(
                            rusqlite::Error::QueryReturnedNoRows,
                        ));
                    }
                }

                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|e| {
                WalletError::StorageError(format!(
                    "Failed to update all wallet scanned blocks: {e}"
                ))
            })?;

        Ok(())
    }
}

// Delegate all other operations to the base storage
#[cfg(feature = "storage")]
#[async_trait]
impl WalletStorage for EnhancedSqliteStorage {
    async fn initialize(&self) -> WalletResult<()> {
        self.base_storage.initialize().await
    }

    async fn save_wallet(&self, wallet: &crate::storage::StoredWallet) -> WalletResult<u32> {
        self.base_storage.save_wallet(wallet).await
    }

    async fn get_wallet_by_id(
        &self,
        wallet_id: u32,
    ) -> WalletResult<Option<crate::storage::StoredWallet>> {
        self.base_storage.get_wallet_by_id(wallet_id).await
    }

    async fn get_wallet_by_name(
        &self,
        name: &str,
    ) -> WalletResult<Option<crate::storage::StoredWallet>> {
        self.base_storage.get_wallet_by_name(name).await
    }

    async fn list_wallets(&self) -> WalletResult<Vec<crate::storage::StoredWallet>> {
        self.base_storage.list_wallets().await
    }

    async fn delete_wallet(&self, wallet_id: u32) -> WalletResult<bool> {
        self.base_storage.delete_wallet(wallet_id).await
    }

    async fn wallet_name_exists(&self, name: &str) -> WalletResult<bool> {
        self.base_storage.wallet_name_exists(name).await
    }

    async fn update_wallet_scanned_block(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> WalletResult<()> {
        self.base_storage
            .update_wallet_scanned_block(wallet_id, block_height)
            .await
    }

    async fn save_transaction(
        &self,
        wallet_id: u32,
        transaction: &WalletTransaction,
    ) -> WalletResult<()> {
        self.base_storage
            .save_transaction(wallet_id, transaction)
            .await
    }

    async fn save_transactions(
        &self,
        wallet_id: u32,
        transactions: &[WalletTransaction],
    ) -> WalletResult<()> {
        self.base_storage
            .save_transactions(wallet_id, transactions)
            .await
    }

    async fn update_transaction(&self, transaction: &WalletTransaction) -> WalletResult<()> {
        self.base_storage.update_transaction(transaction).await
    }

    async fn mark_transaction_spent(
        &self,
        commitment: &CompressedCommitment,
        spent_in_block: u64,
        spent_in_input: usize,
    ) -> WalletResult<bool> {
        self.base_storage
            .mark_transaction_spent(commitment, spent_in_block, spent_in_input)
            .await
    }

    async fn mark_transactions_spent_batch(
        &self,
        spent_commitments: &[(CompressedCommitment, u64, usize)],
    ) -> WalletResult<usize> {
        self.base_storage
            .mark_transactions_spent_batch(spent_commitments)
            .await
    }

    async fn get_transaction_by_commitment(
        &self,
        commitment: &CompressedCommitment,
    ) -> WalletResult<Option<WalletTransaction>> {
        self.base_storage
            .get_transaction_by_commitment(commitment)
            .await
    }

    async fn get_transactions(
        &self,
        filter: Option<crate::storage::TransactionFilter>,
    ) -> WalletResult<Vec<WalletTransaction>> {
        self.base_storage.get_transactions(filter).await
    }

    async fn load_wallet_state(
        &self,
        wallet_id: u32,
    ) -> WalletResult<crate::data_structures::WalletState> {
        self.base_storage.load_wallet_state(wallet_id).await
    }

    async fn get_statistics(&self) -> WalletResult<crate::storage::StorageStats> {
        self.base_storage.get_statistics().await
    }

    async fn get_wallet_statistics(
        &self,
        wallet_id: Option<u32>,
    ) -> WalletResult<crate::storage::StorageStats> {
        self.base_storage.get_wallet_statistics(wallet_id).await
    }

    async fn get_transactions_by_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> WalletResult<Vec<WalletTransaction>> {
        self.base_storage
            .get_transactions_by_block_range(from_block, to_block)
            .await
    }

    async fn get_unspent_transactions(&self) -> WalletResult<Vec<WalletTransaction>> {
        self.base_storage.get_unspent_transactions().await
    }

    async fn get_spent_transactions(&self) -> WalletResult<Vec<WalletTransaction>> {
        self.base_storage.get_spent_transactions().await
    }

    async fn has_commitment(&self, commitment: &CompressedCommitment) -> WalletResult<bool> {
        self.base_storage.has_commitment(commitment).await
    }

    async fn get_highest_block(&self) -> WalletResult<Option<u64>> {
        self.base_storage.get_highest_block().await
    }

    async fn get_lowest_block(&self) -> WalletResult<Option<u64>> {
        self.base_storage.get_lowest_block().await
    }

    async fn clear_all_transactions(&self) -> WalletResult<()> {
        self.base_storage.clear_all_transactions().await
    }

    async fn get_transaction_count(&self) -> WalletResult<usize> {
        self.base_storage.get_transaction_count().await
    }

    async fn close(&self) -> WalletResult<()> {
        self.base_storage.close().await
    }

    async fn save_output(&self, output: &StoredOutput) -> WalletResult<u32> {
        self.base_storage.save_output(output).await
    }

    async fn save_outputs(&self, outputs: &[StoredOutput]) -> WalletResult<Vec<u32>> {
        self.base_storage.save_outputs(outputs).await
    }

    async fn update_output(&self, output: &StoredOutput) -> WalletResult<()> {
        self.base_storage.update_output(output).await
    }

    async fn mark_output_spent(&self, output_id: u32, spent_in_tx_id: u64) -> WalletResult<()> {
        self.base_storage
            .mark_output_spent(output_id, spent_in_tx_id)
            .await
    }

    async fn get_output_by_id(&self, output_id: u32) -> WalletResult<Option<StoredOutput>> {
        self.base_storage.get_output_by_id(output_id).await
    }

    async fn get_output_by_commitment(
        &self,
        commitment: &[u8],
    ) -> WalletResult<Option<StoredOutput>> {
        self.base_storage.get_output_by_commitment(commitment).await
    }

    async fn get_outputs(
        &self,
        filter: Option<crate::storage::OutputFilter>,
    ) -> WalletResult<Vec<StoredOutput>> {
        self.base_storage.get_outputs(filter).await
    }

    async fn get_unspent_outputs(&self, wallet_id: u32) -> WalletResult<Vec<StoredOutput>> {
        self.base_storage.get_unspent_outputs(wallet_id).await
    }

    async fn get_spendable_outputs(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> WalletResult<Vec<StoredOutput>> {
        self.base_storage
            .get_spendable_outputs(wallet_id, block_height)
            .await
    }

    async fn get_spendable_balance(&self, wallet_id: u32, block_height: u64) -> WalletResult<u64> {
        self.base_storage
            .get_spendable_balance(wallet_id, block_height)
            .await
    }

    async fn delete_output(&self, output_id: u32) -> WalletResult<bool> {
        self.base_storage.delete_output(output_id).await
    }

    async fn clear_outputs(&self, wallet_id: u32) -> WalletResult<()> {
        self.base_storage.clear_outputs(wallet_id).await
    }

    async fn get_output_count(&self, wallet_id: u32) -> WalletResult<usize> {
        self.base_storage.get_output_count(wallet_id).await
    }

    async fn store_simple_event(
        &self,
        wallet_id: u32,
        event_type: &str,
        event_data: &str,
    ) -> WalletResult<()> {
        self.base_storage
            .store_simple_event(wallet_id, event_type, event_data)
            .await
    }

    async fn mark_spent_outputs_from_inputs(
        &self,
        wallet_id: u32,
        from_block: u64,
        to_block: u64,
    ) -> WalletResult<usize> {
        self.base_storage
            .mark_spent_outputs_from_inputs(wallet_id, from_block, to_block)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_enhanced_sqlite_creation() {
        let storage = EnhancedSqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_save_all_batches_empty() {
        let storage = EnhancedSqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let result = storage.save_all_batches(&[]).await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_save_all_output_batches_empty() {
        let storage = EnhancedSqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let result = storage.save_all_output_batches(&[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_mark_all_spent_batches_empty() {
        let storage = EnhancedSqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let result = storage.mark_all_spent_batches(&[]).await.unwrap();
        assert_eq!(result, 0);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_update_all_wallet_scanned_blocks_empty() {
        let storage = EnhancedSqliteStorage::new_in_memory().await.unwrap();
        storage.initialize().await.unwrap();

        let result = storage.update_all_wallet_scanned_blocks(&[]).await;
        assert!(result.is_ok());
    }
}
