//! Database storage listener for persisting wallet scan results
//!
//! This listener replicates the functionality of the current storage_backend system
//! by handling scan events and persisting relevant data to a SQLite database.
//! It supports both memory-only and file-based databases, with automatic wallet
//! management and transaction storage.

use async_trait::async_trait;
use std::error::Error;

use crate::events::{EventListener, SharedEvent};
#[cfg(feature = "storage")]
use crate::key_manager::TransactionKeyManager;

#[cfg(feature = "storage")]
use std::collections::{hash_map::Entry, HashMap};

#[cfg(feature = "storage")]
use crate::events::{ErrorRecord, ErrorRecoveryConfig, ErrorRecoveryManager, WalletScanEvent};

#[cfg(feature = "storage")]
use crate::{
    data_structures::types::CompressedCommitment,
    errors::WalletResult,
    storage::{
        event_storage::{EventStorage, StoredEvent},
        SqliteStorage, StoredOutput, WalletStorage,
    },
};

#[cfg(feature = "storage")]
use crate::events::types::{AddressInfo, BlockInfo, OutputData, SpentOutputData, TransactionData};

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use crate::scanning::background_writer::{BackgroundWriter, BackgroundWriterCommand};

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
use tokio::sync::{mpsc, oneshot};

#[cfg(feature = "storage")]
use std::sync::Arc;
#[cfg(feature = "storage")]
use tari_crypto::ristretto::RistrettoSecretKey;
#[cfg(feature = "storage")]
use tari_transaction_components::key_manager::{
    KeyManagerBranch, SerializedKeyString, TariKeyId, TransactionKeyManagerInterface,
};

/// Database storage listener that persists scan results to SQLite
///
/// This listener handles all database operations needed during wallet scanning,
/// including wallet management, transaction storage, output storage, and
/// progress tracking. It replicates the functionality of the current
/// storage_backend system in an event-driven architecture.
///
/// # Features
///
/// - **Cross-platform**: Works on both native and WASM targets
/// - **Background writer**: Uses async background processing on native platforms
/// - **Resume support**: Tracks scan progress for resumable operations
/// - **Wallet management**: Handles multiple wallets with individual contexts
/// - **Error recovery**: Graceful handling of database errors
/// - **Memory bounded**: Configurable batch sizes and cleanup
///
/// # Usage
///
/// ```rust,ignore
/// use lightweight_wallet_libs::events::listeners::DatabaseStorageListener;
/// use lightweight_wallet_libs::events::EventDispatcher;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create with file database
/// let listener = DatabaseStorageListener::new("wallet.db").await?;
///
/// // Or create with in-memory database
/// let listener = DatabaseStorageListener::new_in_memory().await?;
///
/// // Register with event dispatcher
/// let mut dispatcher = EventDispatcher::new();
/// dispatcher.register(Box::new(listener))?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "storage")]
pub struct DatabaseStorageListener {
    /// Database storage interface
    database: Arc<dyn WalletStorage>,
    /// Currently selected wallet ID for operations
    wallet_id: Option<u32>,
    /// Track how many transactions have been saved to avoid duplicates
    #[allow(dead_code)]
    last_saved_transaction_count: usize,
    /// Database path for logging and identification
    database_path: String,
    /// Batch size for bulk operations
    batch_size: usize,
    /// Whether to enable verbose logging
    verbose: bool,
    /// Error recovery manager for database operations
    error_recovery: ErrorRecoveryManager,
    /// Operation metrics for monitoring
    operation_metrics: HashMap<String, usize>,
    /// Whether to enable event auditing (stores events in wallet_events table)
    enable_event_auditing: bool,
    /// Cache for TransactionKeyManager instances
    key_managers: HashMap<u32, Arc<TransactionKeyManager>>,

    /// Background writer for non-WASM32 architectures
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    background_writer: Option<BackgroundWriter>,
}

#[cfg(feature = "storage")]
impl DatabaseStorageListener {
    /// Create a new database storage listener with file-based database
    ///
    /// # Arguments
    /// * `database_path` - Path to the SQLite database file (or ":memory:" for in-memory)
    ///
    /// # Returns
    /// A configured DatabaseStorageListener ready for use
    pub async fn new(database_path: &str) -> WalletResult<Self> {
        let storage = if database_path == ":memory:" {
            SqliteStorage::new_in_memory().await?
        } else {
            SqliteStorage::new(database_path).await?
        };

        storage.initialize().await?;

        Ok(Self {
            database: Arc::new(storage),
            wallet_id: None,
            last_saved_transaction_count: 0,
            database_path: database_path.to_string(),
            batch_size: 50, // Default batch size
            verbose: false,
            error_recovery: ErrorRecoveryManager::with_config(ErrorRecoveryConfig::production()),
            operation_metrics: HashMap::new(),
            enable_event_auditing: false, // Default disabled
            key_managers: HashMap::new(),
            #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
            background_writer: None,
        })
    }

    /// Create a new database storage listener with in-memory database
    ///
    /// # Returns
    /// A configured DatabaseStorageListener using in-memory SQLite database
    pub async fn new_in_memory() -> WalletResult<Self> {
        Self::new(":memory:").await
    }

    /// Create a builder for configuring the database storage listener
    ///
    /// # Returns
    /// A DatabaseStorageListenerBuilder for fluent configuration
    pub fn builder() -> DatabaseStorageListenerBuilder {
        DatabaseStorageListenerBuilder::new()
    }

    /// Set the wallet ID for storage operations
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID to use for subsequent operations
    pub fn set_wallet_id(&mut self, wallet_id: Option<u32>) {
        self.wallet_id = wallet_id;
    }

    /// Get the current wallet ID
    pub fn get_wallet_id(&self) -> Option<u32> {
        self.wallet_id
    }

    /// Set the batch size for bulk operations
    ///
    /// # Arguments
    /// * `batch_size` - Number of items to process in each batch
    pub fn set_batch_size(&mut self, batch_size: usize) {
        self.batch_size = batch_size;
    }

    /// Configure error recovery behavior
    ///
    /// # Arguments
    /// * `config` - Error recovery configuration
    pub fn set_error_recovery_config(&mut self, config: ErrorRecoveryConfig) {
        self.error_recovery = ErrorRecoveryManager::with_config(config);
    }

    /// Get error recovery statistics
    pub fn get_error_stats(&self) -> crate::events::ErrorStats {
        self.error_recovery.get_error_stats()
    }

    /// Get operation metrics
    pub fn get_operation_metrics(&self) -> &HashMap<String, usize> {
        &self.operation_metrics
    }

    /// Clear error recovery history (useful for testing)
    pub fn clear_error_history(&mut self) {
        self.error_recovery.clear_error_history();
        self.operation_metrics.clear();
    }

    /// Enable or disable verbose logging
    ///
    /// # Arguments
    /// * `verbose` - Whether to enable verbose logging
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    /// Enable or disable event auditing (stores events in wallet_events table)
    ///
    /// # Arguments
    /// * `enable` - Whether to enable event auditing
    pub fn set_event_auditing(&mut self, enable: bool) {
        self.enable_event_auditing = enable;
    }

    /// Check if event auditing is enabled
    pub fn is_event_auditing_enabled(&self) -> bool {
        self.enable_event_auditing
    }

    /// Start the background writer service (non-WASM32 only)
    ///
    /// This starts an async background service for database operations
    /// to avoid blocking the main scanning thread.
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn start_background_writer(&mut self) -> WalletResult<()> {
        if self.background_writer.is_some() || self.database_path == ":memory:" {
            return Ok(()); // Already started or in-memory database
        }

        let (command_tx, mut command_rx) = mpsc::unbounded_channel::<BackgroundWriterCommand>();

        // Create a new database connection for the background writer
        let background_database: Box<dyn WalletStorage> =
            Box::new(SqliteStorage::new(&self.database_path).await?);

        // Initialize the background database
        background_database.initialize().await?;

        // Spawn the background writer task
        let join_handle = tokio::spawn(async move {
            BackgroundWriter::background_writer_loop(background_database, &mut command_rx).await;
        });

        self.background_writer = Some(BackgroundWriter {
            command_tx,
            join_handle,
        });

        Ok(())
    }

    /// Stop the background writer service (non-WASM32 only)
    #[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
    pub async fn stop_background_writer(&mut self) -> WalletResult<()> {
        if let Some(writer) = self.background_writer.take() {
            let (response_tx, response_rx) = oneshot::channel();
            if writer
                .command_tx
                .send(BackgroundWriterCommand::Shutdown { response_tx })
                .is_ok()
            {
                let _ = response_rx.await;
            }
            let _ = writer.join_handle.await;
        }
        Ok(())
    }

    /// Handle ScanStarted event
    async fn handle_scan_started(
        &mut self,
        _config: &crate::events::types::ScanConfig,
        _block_range: (u64, u64),
        _wallet_context: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Initialize or select wallet based on context
        // For now, we'll use a simple approach - this could be enhanced
        // to handle more complex wallet selection logic
        if self.wallet_id.is_none() {
            self.log("No wallet selected - scan operations will be skipped");
        }

        Ok(())
    }

    async fn create_transaction_manager(
        &mut self,
        wallet_id: u32,
    ) -> Result<Arc<TransactionKeyManager>, Box<dyn Error + Send + Sync>> {
        match self.key_managers.entry(wallet_id) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let stored_wallet = self
                    .database
                    .get_wallet_by_id(wallet_id)
                    .await?
                    .ok_or_else(|| {
                        crate::WalletError::ResourceNotFound(format!(
                            "Wallet with ID {} not found",
                            wallet_id,
                        ))
                    })?;

                let transaction_key_manager = TransactionKeyManager::build(
                    self.database.clone(),
                    stored_wallet.master_key,
                    tari_common_types::wallet_types::WalletType::default(),
                    wallet_id,
                )
                .await?;

                Ok(entry.insert(Arc::new(transaction_key_manager)).clone())
            }
        }
    }

    /// Handle BlockProcessed event
    async fn handle_block_processed(
        &mut self,
        height: u64,
        _hash: &str,
        _timestamp: u64,
        _processing_duration: std::time::Duration,
        _outputs_count: usize,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Update wallet's scanned block height
        if let Some(wallet_id) = self.wallet_id {
            self.update_wallet_scanned_block(wallet_id, height).await?;
        }

        Ok(())
    }

    /// Handle OutputFound event
    async fn handle_output_found(
        &mut self,
        output_data: &OutputData,
        block_info: &BlockInfo,
        address_info: &AddressInfo,
        transaction_data: &crate::events::types::TransactionData,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(wallet_id) = self.wallet_id {
            // Save the output
            let output_result = self
                .save_output_with_recovery(
                    wallet_id,
                    output_data,
                    block_info,
                    address_info,
                    transaction_data,
                )
                .await;

            // Save the transaction
            let transaction_result = self
                .save_transaction_with_recovery(
                    wallet_id,
                    transaction_data,
                    output_data,
                    block_info,
                )
                .await;

            match (output_result, transaction_result) {
                (Ok(_), Ok(_)) => {
                    // No-op
                }
                (Err(e), _) => {
                    self.log(&format!(
                        "Failed to save output at block {} after retries: {}",
                        block_info.height, e
                    ));
                    return Err(e);
                }
                (_, Err(e)) => {
                    self.log(&format!(
                        "Failed to save transaction at block {} after retries: {}",
                        block_info.height, e
                    ));
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Handle SpentOutputFound event
    ///
    /// Mark the previously found output as spent in the database
    async fn handle_spent_output_found(
        &mut self,
        spent_output_data: &SpentOutputData,
        spending_block_info: &BlockInfo,
        _original_output_info: &OutputData,
        _spending_transaction_data: &TransactionData,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let storage = &self.database;

        // Mark the output as spent in the database

        match self
            .find_output_by_commitment(&spent_output_data.spent_commitment)
            .await
        {
            Ok(Some(output_id)) => {
                // Mark the output as spent using the database ID
                // Note: Using block height as pseudo-transaction ID since we don't have actual spending transaction IDs
                // This will set outputs.status=1 and outputs.spent_in_tx_id=block_height
                if let Err(e) = storage
                    .mark_output_spent(output_id, spending_block_info.height)
                    .await
                {
                    return Err(e.into());
                }

                // Also update the corresponding wallet transaction to mark it as spent
                if let Err(_e) = self
                    .mark_transaction_as_spent(
                        &spent_output_data.spent_commitment,
                        spending_block_info.height,
                        spent_output_data.input_index,
                    )
                    .await
                {
                    // Don't return error here as the output marking succeeded
                }

                // Create an outbound transaction record for the spending transaction
                if let Err(_e) = self
                    .create_outbound_transaction(
                        &spent_output_data.spent_commitment,
                        spending_block_info.height,
                        spent_output_data.input_index,
                        spent_output_data.spent_amount.unwrap_or(0),
                    )
                    .await
                {
                    // Don't return error here as the spent marking succeeded
                }
            }
            Ok(None) => {
                // No-op
            }
            Err(e) => {
                return Err(e);
            }
        }

        Ok(())
    }

    /// Find an output in the database by its commitment
    async fn find_output_by_commitment(
        &self,
        commitment: &str,
    ) -> Result<Option<u32>, Box<dyn Error + Send + Sync>> {
        // Convert hex commitment to bytes
        let commitment_bytes = match hex::decode(commitment) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(format!("Invalid hex commitment: {e}").into());
            }
        };

        // Use the storage method to find the output by commitment
        match self
            .database
            .get_output_by_commitment(&commitment_bytes)
            .await
        {
            Ok(Some(stored_output)) => {
                if let Some(output_id) = stored_output.id {
                    Ok(Some(output_id))
                } else {
                    Ok(None)
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Create an outbound transaction record for a spent output
    async fn create_outbound_transaction(
        &self,
        commitment_hex: &str,
        spending_block: u64,
        input_index: usize,
        value: u64,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        use crate::data_structures::{
            payment_id::PaymentId,
            transaction::{TransactionDirection, TransactionStatus},
            types::CompressedCommitment,
            wallet_transaction::WalletTransaction,
        };

        if let Some(wallet_id) = self.wallet_id {
            // Parse the commitment
            let commitment = CompressedCommitment::from_hex(commitment_hex)
                .map_err(|e| format!("Invalid commitment hex: {e}"))?;

            // Create an outbound transaction record
            let outbound_transaction = WalletTransaction::new(
                spending_block,
                None, // No output_index for spending transaction
                Some(input_index),
                commitment,
                None, // No output hash for outbound transaction
                value,
                PaymentId::Empty, // No payment ID for spending transaction
                TransactionStatus::MinedConfirmed, // Spending is confirmed since it's in a block
                TransactionDirection::Outbound, // This is an outbound transaction (spending)
                true,             // Always mature for spending transactions
                None,             // Spending key
                None,             // Script key
            );

            // Save the outbound transaction to the database
            if let Err(e) = self
                .database
                .save_transaction(wallet_id, &outbound_transaction)
                .await
            {
                return Err(format!("Failed to save outbound transaction: {e}").into());
            }
        }

        Ok(())
    }

    /// Mark a transaction as spent in the wallet_transactions table
    async fn mark_transaction_as_spent(
        &self,
        commitment: &str,
        spent_at_block: u64,
        input_index: usize,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Convert hex commitment to CompressedCommitment
        let commitment_bytes = match hex::decode(commitment) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(format!("Invalid hex commitment: {e}").into());
            }
        };

        // Create CompressedCommitment from bytes (assuming 32-byte commitment)
        if commitment_bytes.len() != 32 {
            return Err("Invalid commitment length".into());
        }

        let mut commitment_array = [0u8; 32];
        commitment_array.copy_from_slice(&commitment_bytes);
        let compressed_commitment = CompressedCommitment::new(commitment_array);

        // Mark the transaction as spent using the storage method
        match self
            .database
            .mark_transaction_spent(&compressed_commitment, spent_at_block, input_index)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => {
                Ok(()) // Not an error if transaction doesn't exist or is already spent
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Handle ScanProgress event
    async fn handle_scan_progress(
        &mut self,
        _current_block: u64,
        _total_blocks: u64,
        _percentage: f64,
        _speed_blocks_per_second: f64,
        _estimated_time_remaining: Option<std::time::Duration>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    /// Handle ScanCompleted event
    async fn handle_scan_completed(
        &mut self,
        _final_statistics: &std::collections::HashMap<String, u64>,
        _success: bool,
        _total_duration: std::time::Duration,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    /// Handle ScanError event
    async fn handle_scan_error(
        &mut self,
        error_message: &str,
        _error_code: Option<&str>,
        block_height: Option<u64>,
        _retry_info: Option<&str>,
        _is_recoverable: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.verbose {
            self.log(&format!(
                "Scan error at block {block_height:?}: {error_message}"
            ));
        }

        // Could implement error logging to database here
        // For now, just log the error
        Ok(())
    }

    /// Handle ScanCancelled event
    async fn handle_scan_cancelled(
        &mut self,
        reason: &str,
        final_statistics: &std::collections::HashMap<String, u64>,
        _partial_completion: Option<f64>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.verbose {
            self.log(&format!(
                "Scan cancelled: reason={reason}, stats={final_statistics:?}"
            ));
        }

        // Perform any cleanup operations
        Ok(())
    }

    /// Convert event data to StoredOutput
    async fn convert_to_stored_output(
        &self,
        wallet_id: u32,
        output_data: &OutputData,
        block_info: &BlockInfo,
        _address_info: &AddressInfo,
        transaction_data: &crate::events::types::TransactionData,
        key_manager: &Arc<TransactionKeyManager>,
    ) -> Result<StoredOutput, Box<dyn Error + Send + Sync>> {
        // Parse commitment from hex string
        use crate::hex_utils::HexEncodable;
        use crate::{data_structures::PaymentId, wallet_scanner::extract_script_data};
        let commitment_hex = output_data.commitment.trim_start_matches("0x");
        let commitment_bytes =
            hex::decode(commitment_hex).map_err(|e| format!("Invalid commitment hex: {e}"))?;

        // Convert to fixed-size array for CompressedCommitment
        if commitment_bytes.len() != 32 {
            return Err(format!(
                "Invalid commitment length: {} (expected 32)",
                commitment_bytes.len()
            )
            .into());
        }
        let mut commitment_array = [0u8; 32];
        commitment_array.copy_from_slice(&commitment_bytes);

        let commitment = CompressedCommitment::new(commitment_array);

        let (input_data, script_lock_height) = if let Some(script) = &output_data.script {
            extract_script_data(script.as_bytes())?
        } else {
            (vec![], 0)
        };

        let commitment_mask_private_key = output_data.commitment_mask_private_key.as_ref().ok_or(
            crate::WalletError::StorageError("No spending key found".to_string()),
        )?;
        let core_commitment_mask_private_key =
            RistrettoSecretKey::try_from(commitment_mask_private_key)
                .map_err(|e| crate::WalletError::ConversionError(e.to_string()))?;
        let commitment_mask_private_key = key_manager
            .import_key(core_commitment_mask_private_key)
            .await?;

        let script_key = match &output_data.script_key {
            // UTXO of a normal transaction
            Some(_) => TariKeyId::Managed {
                branch: KeyManagerBranch::Comms.get_branch_key(),
                index: 0,
            },
            // UTXO of a stealth transaction
            None => TariKeyId::Derived {
                key: SerializedKeyString::from(commitment_mask_private_key.clone().to_string()),
            },
        };
        let payment_id = transaction_data
            .payment_id
            .as_deref()
            .and_then(|hex| PaymentId::from_hex(hex).ok())
            .unwrap_or_default();

        let features_json = serde_json::to_string(&output_data.output_features)?;

        // Create a basic StoredOutput with minimal required fields
        // Note: This is a simplified conversion - in a real implementation,
        // more fields would need to be properly populated from wallet context
        let stored_output = StoredOutput {
            id: None, // Will be set by database
            wallet_id,

            // Core UTXO identification
            commitment: commitment.as_bytes().to_vec(),
            hash: commitment.as_bytes().to_vec(), // Use commitment as hash for now
            value: output_data.amount.unwrap_or(0),

            commitment_mask_key: commitment_mask_private_key.to_string(),
            script_key: script_key.to_string(),

            // Script and covenant data
            script: output_data
                .script
                .as_ref()
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_default(),
            input_data,
            covenant: output_data.covenant.bytes.clone(),

            // Output features and type
            output_type: output_data.features,
            features_json,

            // Maturity and lock constraints
            maturity: output_data.maturity_height.unwrap_or(0),
            script_lock_height,

            // Metadata signature components - would need wallet context
            sender_offset_public_key: output_data.sender_offset_public_key.as_bytes().into(),
            metadata_signature_ephemeral_commitment: output_data
                .metadata_signature
                .ephemeral_commitment
                .clone(),
            metadata_signature_ephemeral_pubkey: output_data
                .metadata_signature
                .ephemeral_pubkey
                .clone(),
            metadata_signature_u_a: output_data.metadata_signature.u_a.clone(),
            metadata_signature_u_x: output_data.metadata_signature.u_x.clone(),
            metadata_signature_u_y: output_data.metadata_signature.u_y.clone(),

            // Payment information
            encrypted_data: output_data.encrypted_value.clone().unwrap_or_default(),
            minimum_value_promise: output_data.minimum_value_promise,
            payment_id: payment_id.to_bytes(),

            // Range proof
            rangeproof: Some(output_data.range_proof.as_bytes().to_vec()),

            // Status and spending tracking
            status: 0, // Unspent
            mined_height: Some(block_info.height),
            block_hash: Some(block_info.hash.clone()),
            spent_in_tx_id: None,

            // Timestamps
            created_at: None,
            updated_at: None,
        };

        Ok(stored_output)
    }

    /// Save outputs to database using architecture-specific method
    async fn save_outputs(&self, outputs: &[StoredOutput]) -> WalletResult<Vec<u32>> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(writer) = &self.background_writer {
                let (response_tx, response_rx) = oneshot::channel();
                writer
                    .command_tx
                    .send(BackgroundWriterCommand::SaveOutputs {
                        outputs: outputs.to_vec(),
                        response_tx,
                    })
                    .map_err(|_| {
                        crate::WalletError::StorageError(
                            "Background writer channel closed".to_string(),
                        )
                    })?;

                return response_rx.await.map_err(|_| {
                    crate::WalletError::StorageError("Background writer response lost".to_string())
                })?;
            }
        }

        // Fallback to direct storage
        self.database.save_outputs(outputs).await
    }

    /// Update wallet's latest scanned block using architecture-specific method
    async fn update_wallet_scanned_block(
        &self,
        wallet_id: u32,
        block_height: u64,
    ) -> WalletResult<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(writer) = &self.background_writer {
                let (response_tx, response_rx) = oneshot::channel();
                writer
                    .command_tx
                    .send(BackgroundWriterCommand::UpdateWalletScannedBlock {
                        wallet_id,
                        block_height,
                        response_tx,
                    })
                    .map_err(|_| {
                        crate::WalletError::StorageError(
                            "Background writer channel closed".to_string(),
                        )
                    })?;

                return response_rx.await.map_err(|_| {
                    crate::WalletError::StorageError("Background writer response lost".to_string())
                })?;
            }
        }

        // Fallback to direct storage
        self.database
            .update_wallet_scanned_block(wallet_id, block_height)
            .await
    }

    /// Log a message (platform-specific)
    fn log(&self, message: &str) {
        let log_message = format!("[DatabaseStorageListener] {message}");

        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(&log_message.into());

        #[cfg(not(target_arch = "wasm32"))]
        println!("{log_message}");
    }

    /// Get database statistics
    pub async fn get_statistics(&self) -> WalletResult<crate::storage::StorageStats> {
        self.database.get_wallet_statistics(self.wallet_id).await
    }

    /// Get the database path
    pub fn database_path(&self) -> &str {
        &self.database_path
    }

    /// Determine if an error is recoverable
    fn is_error_recoverable(&self, error_message: &str) -> bool {
        // Database lock errors are usually temporary
        if error_message.contains("database is locked") {
            return true;
        }

        // Connection errors may be temporary
        if error_message.contains("connection") || error_message.contains("timeout") {
            return true;
        }

        // I/O errors may be temporary
        if error_message.contains("I/O") || error_message.contains("disk") {
            return true;
        }

        // Constraint violations are usually permanent
        if error_message.contains("constraint") || error_message.contains("UNIQUE") {
            return false;
        }

        // Type errors are usually permanent
        if error_message.contains("type") || error_message.contains("parse") {
            return false;
        }

        // By default, consider errors recoverable
        true
    }

    /// Save an output with error recovery
    async fn save_output_with_recovery(
        &mut self,
        wallet_id: u32,
        output_data: &OutputData,
        block_info: &BlockInfo,
        address_info: &AddressInfo,
        transaction_data: &crate::events::types::TransactionData,
    ) -> Result<Vec<u32>, Box<dyn Error + Send + Sync>> {
        let mut attempt = 0;
        let max_attempts = self.error_recovery.get_config().max_retry_attempts;

        loop {
            // Check circuit breaker
            if !self.error_recovery.is_operation_allowed() {
                let error_record = ErrorRecord::new(
                    "Output save operation blocked by circuit breaker".to_string(),
                    false,
                )
                .with_error_code("CIRCUIT_BREAKER_OPEN".to_string());

                self.error_recovery.record_error(error_record);
                return Err("Circuit breaker is open for database operations".into());
            }

            // Attempt the operation
            match self
                .try_save_output(
                    wallet_id,
                    output_data,
                    block_info,
                    address_info,
                    transaction_data,
                )
                .await
            {
                Ok(result) => {
                    self.error_recovery.record_success();
                    return Ok(result);
                }
                Err(e) => {
                    let error_message = e.to_string();
                    let is_recoverable = self.is_error_recoverable(&error_message);

                    let mut error_record = ErrorRecord::new(error_message.clone(), is_recoverable)
                        .with_retry_attempt(attempt)
                        .with_context("operation".to_string(), "save_output".to_string())
                        .with_context("block_height".to_string(), block_info.height.to_string())
                        .with_context("commitment".to_string(), output_data.commitment.clone());

                    // Categorize the error
                    if error_message.contains("database is locked") {
                        error_record = error_record.with_error_code("DATABASE_LOCKED".to_string());
                    } else if error_message.contains("UNIQUE constraint") {
                        error_record = error_record.with_error_code("DUPLICATE_OUTPUT".to_string());
                    } else {
                        error_record = error_record.with_error_code("SAVE_FAILED".to_string());
                    }

                    let should_retry = self.error_recovery.record_error(error_record);

                    if !should_retry
                        || !self.error_recovery.should_retry(attempt, is_recoverable)
                        || attempt >= max_attempts
                    {
                        return Err(e);
                    }

                    // Calculate retry delay
                    let delay = self.error_recovery.calculate_retry_delay(attempt);

                    // Wait before retry
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;

                    attempt += 1;
                }
            }
        }
    }

    /// Save a transaction with error recovery
    async fn save_transaction_with_recovery(
        &mut self,
        wallet_id: u32,
        transaction_data: &crate::events::types::TransactionData,
        output_data: &OutputData,
        block_info: &BlockInfo,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut attempt = 0;
        let max_attempts = self.error_recovery.get_config().max_retry_attempts;

        loop {
            // Check circuit breaker
            if !self.error_recovery.is_operation_allowed() {
                let error_record = ErrorRecord::new(
                    "Transaction save operation blocked by circuit breaker".to_string(),
                    false,
                )
                .with_error_code("CIRCUIT_BREAKER_OPEN".to_string());

                self.error_recovery.record_error(error_record);
                return Err("Circuit breaker is open for database operations".into());
            }

            // Attempt the operation
            match self
                .try_save_transaction(wallet_id, transaction_data, output_data, block_info)
                .await
            {
                Ok(_) => {
                    self.error_recovery.record_success();
                    return Ok(());
                }
                Err(e) => {
                    let error_message = e.to_string();
                    let is_recoverable = self.is_error_recoverable(&error_message);

                    let mut error_record = ErrorRecord::new(error_message.clone(), is_recoverable)
                        .with_retry_attempt(attempt)
                        .with_context("operation".to_string(), "save_transaction".to_string())
                        .with_context("block_height".to_string(), block_info.height.to_string())
                        .with_context("commitment".to_string(), output_data.commitment.clone());

                    // Categorize the error
                    if error_message.contains("database is locked") {
                        error_record = error_record.with_error_code("DATABASE_LOCKED".to_string());
                    } else if error_message.contains("UNIQUE constraint") {
                        error_record =
                            error_record.with_error_code("DUPLICATE_TRANSACTION".to_string());
                    } else {
                        error_record =
                            error_record.with_error_code("TRANSACTION_SAVE_FAILED".to_string());
                    }

                    let should_retry = self.error_recovery.record_error(error_record);

                    if !should_retry
                        || !self.error_recovery.should_retry(attempt, is_recoverable)
                        || attempt >= max_attempts
                    {
                        return Err(e);
                    }

                    // Calculate retry delay
                    let delay = self.error_recovery.calculate_retry_delay(attempt);

                    // Wait before retry
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;

                    attempt += 1;
                }
            }
        }
    }

    /// Try to save a transaction (single attempt)
    async fn try_save_transaction(
        &mut self,
        wallet_id: u32,
        transaction_data: &crate::events::types::TransactionData,
        output_data: &OutputData,
        block_info: &BlockInfo,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Convert event data to WalletTransaction
        let wallet_transaction = self.convert_to_wallet_transaction(
            wallet_id,
            transaction_data,
            output_data,
            block_info,
        )?;

        // Save the transaction to database
        self.database
            .save_transaction(wallet_id, &wallet_transaction)
            .await
            .map_err(|e| e.into())
    }

    /// Convert event data to WalletTransaction
    fn convert_to_wallet_transaction(
        &self,
        _wallet_id: u32,
        transaction_data: &crate::events::types::TransactionData,
        output_data: &OutputData,
        block_info: &BlockInfo,
    ) -> Result<
        crate::data_structures::wallet_transaction::WalletTransaction,
        Box<dyn Error + Send + Sync>,
    > {
        use crate::data_structures::{
            payment_id::PaymentId,
            transaction::{TransactionDirection, TransactionStatus},
            types::CompressedCommitment,
        };
        use crate::hex_utils::HexEncodable;

        // Parse the commitment from hex
        let commitment = CompressedCommitment::from_hex(&output_data.commitment)
            .map_err(|e| format!("Invalid commitment hex: {e}"))?;

        // Parse direction
        let direction = match transaction_data.direction.as_str() {
            "Inbound" => TransactionDirection::Inbound,
            "Outbound" => TransactionDirection::Outbound,
            _ => TransactionDirection::Inbound, // Default to inbound
        };

        // Parse status
        let status = match transaction_data.status.as_str() {
            "MinedConfirmed" => TransactionStatus::MinedConfirmed,
            "MinedUnconfirmed" => TransactionStatus::MinedUnconfirmed,
            "Pending" => TransactionStatus::Pending,
            "Completed" => TransactionStatus::Completed,
            "Imported" => TransactionStatus::Imported,
            _ => TransactionStatus::MinedConfirmed, // Default for found outputs
        };

        // Extract payment ID from transaction data
        let payment_id = if let Some(payment_id_hex) = &transaction_data.payment_id {
            if payment_id_hex.is_empty() || payment_id_hex == "Empty" {
                PaymentId::Empty
            } else {
                // Try to parse the payment ID from hex
                PaymentId::from_hex(payment_id_hex).unwrap_or(PaymentId::Empty)
            }
        } else {
            PaymentId::Empty
        };

        Ok(
            crate::data_structures::wallet_transaction::WalletTransaction {
                block_height: block_info.height,
                output_index: transaction_data.output_index,
                input_index: None,
                commitment,
                output_hash: None,
                value: transaction_data.value,
                payment_id,
                is_spent: false, // For new outputs found during scanning
                spent_in_block: None,
                spent_in_input: None,
                transaction_status: status,
                transaction_direction: direction,
                is_mature: true, // Assume mature for now
                commitment_mask_private_key: None,
                script_key: None,
            },
        )
    }

    /// Try to save an output (single attempt)
    async fn try_save_output(
        &mut self,
        wallet_id: u32,
        output_data: &OutputData,
        block_info: &BlockInfo,
        address_info: &AddressInfo,
        transaction_data: &crate::events::types::TransactionData,
    ) -> Result<Vec<u32>, Box<dyn Error + Send + Sync>> {
        let key_manager = self.create_transaction_manager(wallet_id).await?;
        // Convert event data to StoredOutput
        let stored_output = self
            .convert_to_stored_output(
                wallet_id,
                output_data,
                block_info,
                address_info,
                transaction_data,
                &key_manager,
            )
            .await?;

        // Save the output to database
        self.save_outputs(&[stored_output])
            .await
            .map_err(|e| e.into())
    }

    /// Store an event in the wallet_events table for auditing (if enabled)
    async fn store_event_audit(
        &self,
        event: &WalletScanEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.enable_event_auditing {
            return Ok(());
        }

        // Only store OutputFound and SpentOutputFound events for auditing
        let should_store = matches!(
            event,
            WalletScanEvent::OutputFound { .. } | WalletScanEvent::SpentOutputFound { .. }
        );

        if !should_store {
            return Ok(());
        }

        // Get wallet ID as string for event storage
        let wallet_id = if let Some(id) = self.wallet_id {
            id.to_string()
        } else {
            return Ok(()); // No wallet ID, skip event storage
        };

        // Convert to StoredEvent format
        let event_type = match event {
            WalletScanEvent::OutputFound { .. } => "OUTPUT_FOUND",
            WalletScanEvent::SpentOutputFound { .. } => "SPENT_OUTPUT_FOUND",
            _ => return Ok(()), // Should not happen due to filter above
        };

        let payload_json =
            serde_json::to_string(event).map_err(|e| format!("Failed to serialize event: {e}"))?;

        let metadata = serde_json::json!({
            "listener": "DatabaseStorageListener",
            "event_auditing": true,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        // Create a temporary SQLite connection for event storage
        // Note: This creates a separate connection to the same database file
        // TODO: Consider refactoring to avoid this duplicate connection
        if self.database_path != ":memory:" {
            match SqliteStorage::new(&self.database_path).await {
                Ok(sqlite_storage) => {
                    // Get next sequence number
                    let sequence_number = sqlite_storage
                        .get_next_sequence_number(&wallet_id)
                        .await
                        .map_err(|e| format!("Failed to get sequence number: {e}"))?;

                    // Create stored event
                    let stored_event = StoredEvent {
                        id: None,
                        event_id: uuid::Uuid::new_v4().to_string(),
                        wallet_id: wallet_id.clone(),
                        event_type: event_type.to_string(),
                        sequence_number,
                        payload_json,
                        metadata_json: metadata.to_string(),
                        source: "DatabaseStorageListener".to_string(),
                        correlation_id: None,
                        output_hash: None, // Could be extracted from event if needed
                        timestamp: std::time::SystemTime::now(),
                        stored_at: std::time::SystemTime::now(),
                    };

                    // Store the event
                    sqlite_storage
                        .store_event(&stored_event)
                        .await
                        .map_err(|e| format!("Failed to store event: {e}"))?;
                }
                Err(e) => {
                    // Log error but don't fail the main operation
                    if self.verbose {
                        eprintln!("Warning: Failed to create event storage connection: {e}");
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "storage")]
#[async_trait]
impl EventListener for DatabaseStorageListener {
    async fn handle_event(
        &mut self,
        event: &SharedEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match event.as_ref() {
            WalletScanEvent::ScanStarted {
                config,
                block_range,
                wallet_context,
                ..
            } => {
                self.handle_scan_started(config, *block_range, wallet_context)
                    .await
            }
            WalletScanEvent::BlockProcessed {
                height,
                hash,
                timestamp,
                processing_duration,
                outputs_count,
                ..
            } => {
                self.handle_block_processed(
                    *height,
                    hash,
                    *timestamp,
                    *processing_duration,
                    *outputs_count,
                )
                .await
            }
            WalletScanEvent::OutputFound {
                output_data,
                block_info,
                address_info,
                transaction_data,
                ..
            } => {
                // Store event for auditing if enabled
                if let Err(e) = self.store_event_audit(event.as_ref()).await {
                    if self.verbose {
                        eprintln!("Warning: Failed to store event audit: {e}");
                    }
                }

                self.handle_output_found(output_data, block_info, address_info, transaction_data)
                    .await
            }
            WalletScanEvent::SpentOutputFound {
                spent_output_data,
                spending_block_info,
                original_output_info,
                spending_transaction_data,
                ..
            } => {
                // Store event for auditing if enabled
                if let Err(e) = self.store_event_audit(event.as_ref()).await {
                    if self.verbose {
                        eprintln!("Warning: Failed to store event audit: {e}");
                    }
                }

                self.handle_spent_output_found(
                    spent_output_data,
                    spending_block_info,
                    original_output_info,
                    spending_transaction_data,
                )
                .await
            }
            WalletScanEvent::ScanProgress {
                current_block,
                total_blocks,
                percentage,
                speed_blocks_per_second,
                estimated_time_remaining,
                ..
            } => {
                self.handle_scan_progress(
                    *current_block,
                    *total_blocks,
                    *percentage,
                    *speed_blocks_per_second,
                    *estimated_time_remaining,
                )
                .await
            }
            WalletScanEvent::ScanCompleted {
                final_statistics,
                success,
                total_duration,
                ..
            } => {
                self.handle_scan_completed(final_statistics, *success, *total_duration)
                    .await
            }
            WalletScanEvent::ScanError {
                error_message,
                error_code,
                block_height,
                retry_info,
                is_recoverable,
                ..
            } => {
                self.handle_scan_error(
                    error_message,
                    error_code.as_deref(),
                    *block_height,
                    retry_info.as_deref(),
                    *is_recoverable,
                )
                .await
            }
            WalletScanEvent::ScanCancelled {
                reason,
                final_statistics,
                partial_completion,
                ..
            } => {
                self.handle_scan_cancelled(reason, final_statistics, *partial_completion)
                    .await
            }
        }
    }

    fn name(&self) -> &'static str {
        "DatabaseStorageListener"
    }

    /// Only handle events that require database operations
    fn wants_event(&self, event: &SharedEvent) -> bool {
        match event.as_ref() {
            WalletScanEvent::ScanStarted { .. }
            | WalletScanEvent::BlockProcessed { .. }
            | WalletScanEvent::OutputFound { .. }
            | WalletScanEvent::SpentOutputFound { .. }
            | WalletScanEvent::ScanProgress { .. }
            | WalletScanEvent::ScanCompleted { .. }
            | WalletScanEvent::ScanError { .. }
            | WalletScanEvent::ScanCancelled { .. } => true,
        }
    }
}

/// Builder for configuring DatabaseStorageListener
#[cfg(feature = "storage")]
pub struct DatabaseStorageListenerBuilder {
    database_path: String,
    batch_size: usize,
    verbose: bool,
    enable_wal_mode: bool,
    auto_start_background_writer: bool,
    enable_event_auditing: bool,
}

#[cfg(feature = "storage")]
impl DatabaseStorageListenerBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            database_path: ":memory:".to_string(),
            batch_size: 50,
            verbose: false,
            enable_wal_mode: false,
            auto_start_background_writer: true,
            enable_event_auditing: false,
        }
    }

    /// Set the database path
    pub fn database_path(mut self, path: &str) -> Self {
        self.database_path = path.to_string();
        self
    }

    /// Set the batch size for bulk operations
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Enable verbose logging
    pub fn verbose(mut self, enabled: bool) -> Self {
        self.verbose = enabled;
        self
    }

    /// Enable WAL mode for better concurrency (not implemented yet)
    pub fn enable_wal_mode(mut self, enabled: bool) -> Self {
        self.enable_wal_mode = enabled;
        self
    }

    /// Automatically start background writer on non-WASM32 platforms
    pub fn auto_start_background_writer(mut self, enabled: bool) -> Self {
        self.auto_start_background_writer = enabled;
        self
    }

    /// Enable event auditing (stores events in wallet_events table)
    pub fn event_auditing(mut self, enabled: bool) -> Self {
        self.enable_event_auditing = enabled;
        self
    }

    /// Apply memory-only preset configuration for testing and development
    ///
    /// This preset:
    /// - Uses in-memory database (":memory:")
    /// - Sets small batch size (25) for responsive testing
    /// - Disables verbose logging for cleaner test output
    /// - Disables WAL mode (not applicable for memory DB)
    /// - Enables background writer for full feature testing
    ///
    /// Perfect for unit tests and development environments.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = DatabaseStorageListener::builder()
    ///     .memory_preset()
    ///     .build()
    ///     .await?;
    /// ```
    pub fn memory_preset(mut self) -> Self {
        self.database_path = ":memory:".to_string();
        self.batch_size = 25;
        self.verbose = false;
        self.enable_wal_mode = false;
        self.auto_start_background_writer = true;
        self
    }

    /// Apply production preset configuration for high-performance persistent storage
    ///
    /// This preset:
    /// - Uses file-based database (user must set path)
    /// - Sets large batch size (200) for optimal throughput
    /// - Disables verbose logging for production efficiency
    /// - Enables WAL mode for better concurrency
    /// - Enables background writer for asynchronous I/O
    ///
    /// Optimized for production wallet scanning with maximum performance.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = DatabaseStorageListener::builder()
    ///     .production_preset()
    ///     .database_path("production_wallet.db")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn production_preset(mut self) -> Self {
        // Keep current database_path (user should set explicitly)
        self.batch_size = 200;
        self.verbose = false;
        self.enable_wal_mode = true;
        self.auto_start_background_writer = true;
        self
    }

    /// Apply development preset configuration for debugging and analysis
    ///
    /// This preset:
    /// - Uses file-based database (user must set path)
    /// - Sets small batch size (10) for detailed observation
    /// - Enables verbose logging for debugging
    /// - Disables WAL mode for simpler debugging
    /// - Enables background writer with full logging
    ///
    /// Ideal for development, debugging, and detailed analysis scenarios.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = DatabaseStorageListener::builder()
    ///     .development_preset()
    ///     .database_path("debug_wallet.db")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn development_preset(mut self) -> Self {
        // Keep current database_path (user should set explicitly)
        self.batch_size = 10;
        self.verbose = true;
        self.enable_wal_mode = false;
        self.auto_start_background_writer = true;
        self
    }

    /// Apply testing preset configuration for integration tests
    ///
    /// This preset:
    /// - Uses temporary file database (user should set unique path)
    /// - Sets medium batch size (50) for balanced testing
    /// - Enables verbose logging for test debugging
    /// - Disables WAL mode for test reliability
    /// - Disables background writer for synchronous testing
    ///
    /// Suitable for integration tests that need file persistence but want
    /// predictable, synchronous behavior.
    ///
    /// # Example
    /// ```rust,ignore
    /// let temp_path = format!("test_wallet_{}.db", uuid::Uuid::new_v4());
    /// let listener = DatabaseStorageListener::builder()
    ///     .testing_preset()
    ///     .database_path(&temp_path)
    ///     .build()
    ///     .await?;
    /// ```
    pub fn testing_preset(mut self) -> Self {
        // Keep current database_path (user should set explicitly)
        self.batch_size = 50;
        self.verbose = true;
        self.enable_wal_mode = false;
        self.auto_start_background_writer = false;
        self
    }

    /// Apply performance preset configuration for benchmarking and stress testing
    ///
    /// This preset:
    /// - Uses file-based database (user must set path)
    /// - Sets very large batch size (500) for maximum throughput
    /// - Disables verbose logging to minimize I/O overhead
    /// - Enables WAL mode for best write performance
    /// - Enables background writer for optimal async performance
    ///
    /// Designed for performance testing and high-throughput scenarios.
    ///
    /// # Example
    /// ```rust,ignore
    /// let listener = DatabaseStorageListener::builder()
    ///     .performance_preset()
    ///     .database_path("benchmark_wallet.db")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn performance_preset(mut self) -> Self {
        // Keep current database_path (user should set explicitly)
        self.batch_size = 500;
        self.verbose = false;
        self.enable_wal_mode = true;
        self.auto_start_background_writer = true;
        self
    }

    /// Build the configured DatabaseStorageListener
    pub async fn build(self) -> WalletResult<DatabaseStorageListener> {
        let mut listener = DatabaseStorageListener::new(&self.database_path).await?;

        listener.set_batch_size(self.batch_size);
        listener.set_verbose(self.verbose);
        listener.set_event_auditing(self.enable_event_auditing);

        #[cfg(all(feature = "grpc", not(target_arch = "wasm32")))]
        if self.auto_start_background_writer {
            listener.start_background_writer().await?;
        }

        Ok(listener)
    }
}

#[cfg(feature = "storage")]
impl Default for DatabaseStorageListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Stub implementation for when storage feature is not enabled
#[cfg(not(feature = "storage"))]
#[derive(Debug)]
pub struct DatabaseStorageListener;

#[cfg(not(feature = "storage"))]
impl DatabaseStorageListener {
    pub async fn new(_database_path: &str) -> Result<Self, String> {
        Err("Database storage requires 'storage' feature to be enabled".to_string())
    }

    pub async fn new_in_memory() -> Result<Self, String> {
        Err("Database storage requires 'storage' feature to be enabled".to_string())
    }
}

#[cfg(not(feature = "storage"))]
#[async_trait]
impl EventListener for DatabaseStorageListener {
    async fn handle_event(
        &mut self,
        _event: &SharedEvent,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("Database storage requires 'storage' feature to be enabled".into())
    }

    fn name(&self) -> &'static str {
        "DatabaseStorageListener (disabled)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "storage")]
    mod storage_tests {
        use super::*;
        use crate::events::types::*;
        use std::sync::Arc;
        use std::time::Duration;

        #[tokio::test]
        async fn test_database_storage_listener_creation() {
            let listener = DatabaseStorageListener::new_in_memory().await;
            assert!(listener.is_ok());

            let listener = listener.unwrap();
            assert_eq!(listener.name(), "DatabaseStorageListener");
            assert_eq!(listener.database_path(), ":memory:");
            assert_eq!(listener.get_wallet_id(), None);
        }

        #[tokio::test]
        async fn test_database_storage_listener_builder() {
            let listener = DatabaseStorageListener::builder()
                .database_path(":memory:")
                .batch_size(100)
                .verbose(true)
                .auto_start_background_writer(false)
                .build()
                .await;

            assert!(listener.is_ok());
            let listener = listener.unwrap();
            assert_eq!(listener.database_path(), ":memory:");
        }

        #[tokio::test]
        async fn test_wallet_id_management() {
            let mut listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            assert_eq!(listener.get_wallet_id(), None);

            listener.set_wallet_id(Some(42));
            assert_eq!(listener.get_wallet_id(), Some(42));

            listener.set_wallet_id(None);
            assert_eq!(listener.get_wallet_id(), None);
        }

        #[tokio::test]
        async fn test_event_filtering() {
            let listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            // All events should be wanted by database storage listener
            let scan_started = Arc::new(WalletScanEvent::scan_started(
                "test_wallet_id",
                ScanConfig::default(),
                (0, 100),
                "test_wallet".to_string(),
            ));
            assert!(listener.wants_event(&scan_started));

            let block_processed = Arc::new(WalletScanEvent::block_processed(
                "test_wallet_id",
                100,
                "block_hash".to_string(),
                1234567890,
                Duration::from_millis(100),
                5,
            ));
            assert!(listener.wants_event(&block_processed));
        }

        #[tokio::test]
        async fn test_handle_scan_started_event() {
            let mut listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            let event = Arc::new(WalletScanEvent::scan_started(
                "test_wallet_id",
                ScanConfig::default(),
                (0, 100),
                "test_wallet".to_string(),
            ));

            let result = listener.handle_event(&event).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_convert_to_stored_output() {
            let mut listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            let output_data = OutputData::new(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                "range_proof_data".to_string(),
                1,
                true,
            )
            .with_amount(1000)
            .with_key_index(5)
            .with_maturity_height(5);

            let block_info = BlockInfo::new(12345, "block_hash".to_string(), 1697123456, 2);

            let address_info = AddressInfo::new(
                "tari1xyz123...".to_string(),
                "stealth".to_string(),
                "mainnet".to_string(),
            );

            let key_manager = listener.create_transaction_manager(0).await.unwrap();
            let transaction_data = crate::events::types::TransactionData::default();
            let result = listener
                .convert_to_stored_output(
                    1,
                    &output_data,
                    &block_info,
                    &address_info,
                    &transaction_data,
                    &key_manager,
                )
                .await;

            assert!(result.is_ok());
            let stored_output = result.unwrap();
            assert_eq!(stored_output.wallet_id, 1);
            assert_eq!(stored_output.value, 1000);
            assert_eq!(stored_output.mined_height, Some(12345));
            assert_eq!(stored_output.output_type, 1);
            assert_eq!(stored_output.maturity, 5);
            assert_eq!(stored_output.status, 0); // Unspent
        }

        #[tokio::test]
        async fn test_get_statistics() {
            let listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            let stats = listener.get_statistics().await;
            assert!(stats.is_ok());

            let stats = stats.unwrap();
            assert_eq!(stats.total_transactions, 0);
            assert_eq!(stats.current_balance, 0);
        }

        #[cfg(all(feature = "grpc", not(target_arch = "wasm32")))]
        #[tokio::test]
        async fn test_background_writer_lifecycle() {
            let mut listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            // Start background writer (should be no-op for in-memory database)
            let result = listener.start_background_writer().await;
            assert!(result.is_ok());

            // Stop background writer
            let result = listener.stop_background_writer().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_database_storage_listener_builder_presets() {
            // Test memory preset
            let memory_listener = DatabaseStorageListener::builder()
                .memory_preset()
                .build()
                .await;
            assert!(memory_listener.is_ok());
            let listener = memory_listener.unwrap();
            assert_eq!(listener.batch_size, 25);
            assert!(!listener.verbose);

            // Test production preset
            let production_builder = DatabaseStorageListener::builder()
                .production_preset()
                .database_path("test_production.db");
            // We can test the builder configuration without building
            assert_eq!(production_builder.batch_size, 200);
            assert!(!production_builder.verbose);
            assert!(production_builder.enable_wal_mode);
            assert!(production_builder.auto_start_background_writer);

            // Test development preset
            let development_builder = DatabaseStorageListener::builder()
                .development_preset()
                .database_path("test_development.db");
            assert_eq!(development_builder.batch_size, 10);
            assert!(development_builder.verbose);
            assert!(!development_builder.enable_wal_mode);
            assert!(development_builder.auto_start_background_writer);

            // Test testing preset
            let testing_builder = DatabaseStorageListener::builder()
                .testing_preset()
                .database_path("test_testing.db");
            assert_eq!(testing_builder.batch_size, 50);
            assert!(testing_builder.verbose);
            assert!(!testing_builder.enable_wal_mode);
            assert!(!testing_builder.auto_start_background_writer);

            // Test performance preset
            let performance_builder = DatabaseStorageListener::builder()
                .performance_preset()
                .database_path("test_performance.db");
            assert_eq!(performance_builder.batch_size, 500);
            assert!(!performance_builder.verbose);
            assert!(performance_builder.enable_wal_mode);
            assert!(performance_builder.auto_start_background_writer);
        }

        #[tokio::test]
        async fn test_database_storage_listener_builder_preset_chaining() {
            let listener = DatabaseStorageListener::builder()
                .production_preset() // Start with production preset
                .batch_size(100) // Override batch size
                .verbose(true) // Override verbose
                .database_path(":memory:") // Use memory for test
                .build()
                .await;

            assert!(listener.is_ok());
            let listener = listener.unwrap();

            // Should have the overridden values
            assert_eq!(listener.batch_size, 100);
            assert!(listener.verbose);
        }

        #[tokio::test]
        async fn test_database_storage_listener_builder_basic() {
            let listener = DatabaseStorageListener::builder()
                .database_path(":memory:")
                .batch_size(75)
                .verbose(true)
                .build()
                .await;

            assert!(listener.is_ok());
            let listener = listener.unwrap();
            assert_eq!(listener.batch_size, 75);
            assert!(listener.verbose);
            assert_eq!(listener.name(), "DatabaseStorageListener");
        }

        #[tokio::test]
        async fn test_error_recovery_functionality() {
            let mut listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            // Test initial error stats
            let stats = listener.get_error_stats();
            assert_eq!(stats.total_errors, 0);
            assert_eq!(stats.consecutive_errors, 0);
            assert_eq!(stats.total_recoveries, 0);

            // Test operation metrics
            let metrics = listener.get_operation_metrics();
            assert!(metrics.is_empty());

            // Test error recovery configuration
            listener.set_error_recovery_config(ErrorRecoveryConfig::development());
            let stats = listener.get_error_stats();
            assert_eq!(stats.total_errors, 0); // Should still be 0 after config change

            // Test clearing error history
            listener.clear_error_history();
            let stats = listener.get_error_stats();
            assert_eq!(stats.total_errors, 0);
            assert_eq!(stats.consecutive_errors, 0);
        }

        #[tokio::test]
        async fn test_error_recoverability_classification() {
            let listener = DatabaseStorageListener::new_in_memory().await.unwrap();

            // Test recoverable errors
            assert!(listener.is_error_recoverable("database is locked"));
            assert!(listener.is_error_recoverable("connection timeout"));
            assert!(listener.is_error_recoverable("I/O error"));
            assert!(listener.is_error_recoverable("disk full"));

            // Test non-recoverable errors
            assert!(!listener.is_error_recoverable("UNIQUE constraint failed"));
            assert!(!listener.is_error_recoverable("constraint violation"));
            assert!(!listener.is_error_recoverable("type mismatch"));
            assert!(!listener.is_error_recoverable("parse error"));

            // Test default case (should be recoverable)
            assert!(listener.is_error_recoverable("unknown error"));
        }
    }

    #[cfg(not(feature = "storage"))]
    mod no_storage_tests {
        use super::*;

        #[tokio::test]
        async fn test_database_storage_listener_requires_storage_feature() {
            let result = DatabaseStorageListener::new("test.db").await;
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("storage"));
        }

        #[tokio::test]
        async fn test_in_memory_requires_storage_feature() {
            let result = DatabaseStorageListener::new_in_memory().await;
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("storage"));
        }
    }
}
