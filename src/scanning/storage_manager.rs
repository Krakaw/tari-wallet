//! Storage management for scanning operations and scan results
//!
//! This module provides storage abstractions specifically designed for the scanner library,
//! building on top of the existing wallet storage infrastructure.

#[cfg(feature = "storage")]
use async_trait::async_trait;

#[cfg(feature = "storage")]
use crate::data_structures::{
    wallet_output::LightweightWalletOutput,
    wallet_transaction::WalletState,
};

#[cfg(feature = "storage")]
use crate::errors::LightweightWalletResult;

#[cfg(feature = "storage")]
use super::scan_results::ScanResults;

/// Storage manager trait for unified storage operations in the scanner library
#[cfg(feature = "storage")]
#[async_trait(?Send)]
pub trait StorageManager: Send + Sync {
    /// Save scan results to storage
    async fn save_scan_results(&mut self, results: &ScanResults) -> LightweightWalletResult<()>;
    
    /// Save a single wallet output to storage
    async fn save_wallet_output(&mut self, wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<()>;
    
    /// Save multiple wallet outputs in batch
    async fn save_wallet_outputs(&mut self, wallet_id: u32, outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()>;
    
    /// Save wallet state (transactions and balances)
    async fn save_wallet_state(&mut self, wallet_id: u32, state: &WalletState) -> LightweightWalletResult<()>;
    
    /// Mark output as spent by commitment
    async fn mark_output_spent(&mut self, commitment: &[u8], block_height: u64) -> LightweightWalletResult<()>;
    
    /// Get wallet state with current balances
    async fn get_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState>;
    
    /// Update the latest scanned block for a wallet
    async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()>;
    
    /// Get the latest scanned block for a wallet
    async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>>;
}

/// Mock storage manager for testing and non-storage scenarios
#[cfg(feature = "storage")]
#[derive(Debug, Default)]
pub struct MockStorageManager {
    latest_scanned_blocks: std::collections::HashMap<u32, u64>,
}

#[cfg(feature = "storage")]
impl MockStorageManager {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "storage")]
#[async_trait(?Send)]
impl StorageManager for MockStorageManager {
    async fn save_scan_results(&mut self, _results: &ScanResults) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn save_wallet_output(&mut self, _wallet_id: u32, _output: &LightweightWalletOutput) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn save_wallet_outputs(&mut self, _wallet_id: u32, _outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn save_wallet_state(&mut self, _wallet_id: u32, _state: &WalletState) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn mark_output_spent(&mut self, _commitment: &[u8], _block_height: u64) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn get_wallet_state(&self, _wallet_id: u32) -> LightweightWalletResult<WalletState> {
        // Mock implementation - return empty wallet state
        Ok(WalletState::new())
    }
    
    async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()> {
        self.latest_scanned_blocks.insert(wallet_id, block_height);
        Ok(())
    }
    
    async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>> {
        Ok(self.latest_scanned_blocks.get(&wallet_id).copied())
    }
}

// Storage implementations are only available with the storage feature
#[cfg(feature = "storage")]
mod storage_adapters {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use std::time::{Duration, Instant};
    use crate::storage::WalletStorage;
    use crate::errors::LightweightWalletError;

    /// Background writer adapter for high-performance scanning with non-blocking writes
    pub struct BackgroundWriterAdapter {
        /// Channel for sending storage commands to background task
        command_sender: mpsc::UnboundedSender<StorageCommand>,
        /// Handle to the background storage task
        _task_handle: tokio::task::JoinHandle<()>,
        /// Reference to the underlying storage for read operations
        storage: Arc<dyn WalletStorage>,
    }

    /// Commands sent to the background storage writer
    #[derive(Debug)]
    enum StorageCommand {
        SaveScanResults {
            results: ScanResults,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        SaveWalletOutput {
            wallet_id: u32,
            output: LightweightWalletOutput,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        SaveWalletOutputs {
            wallet_id: u32,
            outputs: Vec<LightweightWalletOutput>,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        SaveWalletState {
            wallet_id: u32,
            state: WalletState,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        MarkOutputSpent {
            commitment: Vec<u8>,
            block_height: u64,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        UpdateScannedBlock {
            wallet_id: u32,
            block_height: u64,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        Shutdown,
    }

    impl BackgroundWriterAdapter {
        /// Create a new background writer adapter
        pub fn new(storage: Arc<dyn WalletStorage>) -> Self {
            let (command_sender, mut command_receiver) = mpsc::unbounded_channel();
            let storage_clone = storage.clone();
            
            // Spawn background task for processing storage commands
            let task_handle = tokio::spawn(async move {
                let mut stats = WriterStats::default();
                
                while let Some(command) = command_receiver.recv().await {
                    let start_time = Instant::now();
                    
                    match command {
                        StorageCommand::SaveScanResults { results, response } => {
                            let result = Self::handle_save_scan_results(&*storage_clone, &results).await;
                            stats.record_operation("save_scan_results", start_time.elapsed());
                            let _ = response.send(result);
                        }
                        StorageCommand::SaveWalletOutput { wallet_id, output, response } => {
                            let result = Self::handle_save_wallet_output(&*storage_clone, wallet_id, &output).await;
                            stats.record_operation("save_wallet_output", start_time.elapsed());
                            let _ = response.send(result);
                        }
                        StorageCommand::SaveWalletOutputs { wallet_id, outputs, response } => {
                            let result = Self::handle_save_wallet_outputs(&*storage_clone, wallet_id, &outputs).await;
                            stats.record_operation("save_wallet_outputs", start_time.elapsed());
                            let _ = response.send(result);
                        }
                        StorageCommand::SaveWalletState { wallet_id, state, response } => {
                            let result = Self::handle_save_wallet_state(&*storage_clone, wallet_id, &state).await;
                            stats.record_operation("save_wallet_state", start_time.elapsed());
                            let _ = response.send(result);
                        }
                        StorageCommand::MarkOutputSpent { commitment, block_height, response } => {
                            let result = Self::handle_mark_output_spent(&*storage_clone, &commitment, block_height).await;
                            stats.record_operation("mark_output_spent", start_time.elapsed());
                            let _ = response.send(result);
                        }
                        StorageCommand::UpdateScannedBlock { wallet_id, block_height, response } => {
                            let result = storage_clone.update_wallet_scanned_block(wallet_id, block_height).await;
                            stats.record_operation("update_scanned_block", start_time.elapsed());
                            let _ = response.send(result);
                        }
                        StorageCommand::Shutdown => {
                            #[cfg(feature = "tracing")]
                            tracing::info!("Background storage writer shutting down. Stats: {:?}", stats);
                            break;
                        }
                    }
                }
            });
            
            Self {
                command_sender,
                _task_handle: task_handle,
                storage,
            }
        }
        
        /// Send a command to the background writer and wait for response
        async fn send_command(&self, command: StorageCommand) -> LightweightWalletResult<()> {
            let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
            
            // Wrap the command with the response channel
            let command_with_response = match command {
                StorageCommand::SaveScanResults { results, .. } => {
                    StorageCommand::SaveScanResults { results, response: response_sender }
                }
                StorageCommand::SaveWalletOutput { wallet_id, output, .. } => {
                    StorageCommand::SaveWalletOutput { wallet_id, output, response: response_sender }
                }
                StorageCommand::SaveWalletOutputs { wallet_id, outputs, .. } => {
                    StorageCommand::SaveWalletOutputs { wallet_id, outputs, response: response_sender }
                }
                StorageCommand::SaveWalletState { wallet_id, state, .. } => {
                    StorageCommand::SaveWalletState { wallet_id, state, response: response_sender }
                }
                StorageCommand::MarkOutputSpent { commitment, block_height, .. } => {
                    StorageCommand::MarkOutputSpent { commitment, block_height, response: response_sender }
                }
                StorageCommand::UpdateScannedBlock { wallet_id, block_height, .. } => {
                    StorageCommand::UpdateScannedBlock { wallet_id, block_height, response: response_sender }
                }
                StorageCommand::Shutdown => {
                    return Err(LightweightWalletError::InternalError("Invalid command for send_command".to_string()));
                }
            };
            
            self.command_sender.send(command_with_response)
                .map_err(|_| LightweightWalletError::InternalError("Background writer channel closed".to_string()))?;
                
            response_receiver.await
                .map_err(|_| LightweightWalletError::InternalError("Background writer response channel closed".to_string()))?
        }
        
        /// Handle saving scan results in background task
        async fn handle_save_scan_results(
            storage: &dyn WalletStorage,
            results: &ScanResults,
        ) -> LightweightWalletResult<()> {
            // Save the wallet state which contains all the transactions
            if !results.wallet_state.transactions.is_empty() {
                // For now, assume wallet_id = 1 - this would need to be passed in properly
                storage.save_transactions(1, &results.wallet_state.transactions).await?;
            }
            
            // Update the latest scanned block based on scan configuration
            let latest_block = results.scan_config_summary.start_height + results.scan_config_summary.total_blocks_scanned;
            if latest_block > results.scan_config_summary.start_height {
                storage.update_wallet_scanned_block(1, latest_block - 1).await?;
            }
            
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Saved scan results: {} transactions, {} blocks scanned (blocks {}-{})",
                results.wallet_state.transactions.len(),
                results.scan_config_summary.total_blocks_scanned,
                results.scan_config_summary.start_height,
                latest_block - 1
            );
            
            Ok(())
        }
        
        /// Handle saving a single wallet output in background task
        async fn handle_save_wallet_output(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            output: &LightweightWalletOutput,
        ) -> LightweightWalletResult<()> {
            let stored_output = Self::convert_to_stored_output(wallet_id, output)?;
            storage.save_output(&stored_output).await?;
            Ok(())
        }
        
        /// Handle saving multiple wallet outputs in background task
        async fn handle_save_wallet_outputs(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            outputs: &[LightweightWalletOutput],
        ) -> LightweightWalletResult<()> {
            let stored_outputs: Result<Vec<_>, _> = outputs.iter()
                .map(|output| Self::convert_to_stored_output(wallet_id, output))
                .collect();
            
            let stored_outputs = stored_outputs?;
            storage.save_outputs(&stored_outputs).await?;
            Ok(())
        }
        
        /// Handle saving wallet state in background task
        async fn handle_save_wallet_state(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            state: &WalletState,
        ) -> LightweightWalletResult<()> {
            // Save all transactions in the wallet state
            storage.save_transactions(wallet_id, &state.transactions).await
        }
        
        /// Handle marking output as spent in background task
        async fn handle_mark_output_spent(
            storage: &dyn WalletStorage,
            commitment: &[u8],
            block_height: u64,
        ) -> LightweightWalletResult<()> {
            use crate::data_structures::types::CompressedCommitment;
            
            // Convert commitment bytes to CompressedCommitment
            if commitment.len() != 32 {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "commitment".to_string(),
                    value: hex::encode(commitment),
                    message: "Commitment must be exactly 32 bytes".to_string(),
                });
            }
            
            let mut commitment_array = [0u8; 32];
            commitment_array.copy_from_slice(commitment);
            let compressed_commitment = CompressedCommitment::new(commitment_array);
            
            // Mark the transaction as spent using the compressed commitment
            let _result = storage.mark_transaction_spent(&compressed_commitment, block_height, 0).await?;
            
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Marked output spent: commitment={}, block_height={}",
                hex::encode(commitment),
                block_height
            );
            
            Ok(())
        }
        
        /// Shutdown the background writer gracefully
        pub async fn shutdown(&self) {
            let _ = self.command_sender.send(StorageCommand::Shutdown);
        }
        
        /// Convert LightweightWalletOutput to StoredOutput format
        fn convert_to_stored_output(wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<crate::storage::storage_trait::StoredOutput> {
            use crate::storage::storage_trait::StoredOutput;
            use hex;
            
            // Create a dummy commitment and hash - in practice these would come from actual output data
            let commitment_hex = match &output.spending_key_id {
                crate::data_structures::wallet_output::LightweightKeyId::String(s) => {
                    // Use a hash of the string as a placeholder commitment
                    use blake2::digest::{Digest, FixedOutput};
                    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
                    hasher.update(s.as_bytes());
                    hex::encode(hasher.finalize_fixed())
                }
                crate::data_structures::wallet_output::LightweightKeyId::PublicKey(pk) => {
                    hex::encode(pk.as_bytes())
                }
                crate::data_structures::wallet_output::LightweightKeyId::Zero => {
                    hex::encode([0u8; 32])
                }
            };
            
            let script_key_hex = match &output.script_key_id {
                crate::data_structures::wallet_output::LightweightKeyId::String(s) => {
                    // Use a hash of the string as a placeholder key
                    use blake2::digest::{Digest, FixedOutput};
                    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
                    hasher.update(s.as_bytes());
                    hex::encode(hasher.finalize_fixed())
                }
                crate::data_structures::wallet_output::LightweightKeyId::PublicKey(pk) => {
                    hex::encode(pk.as_bytes())
                }
                crate::data_structures::wallet_output::LightweightKeyId::Zero => {
                    hex::encode([0u8; 32])
                }
            };
            
            let commitment_bytes = hex::decode(&commitment_hex)
                .map_err(|e| LightweightWalletError::InternalError(format!("Invalid commitment hex: {}", e)))?;
            
            Ok(StoredOutput {
                id: None,
                wallet_id,
                commitment: commitment_bytes.clone(),
                hash: commitment_bytes, // Use same as commitment for now
                value: output.value.as_u64(),
                spending_key: commitment_hex, // Use commitment as placeholder spending key
                script_private_key: script_key_hex,
                script: output.script.bytes.clone(),
                input_data: output.input_data.bytes(),
                covenant: output.covenant.bytes.clone(),
                output_type: match output.features.output_type {
                    crate::data_structures::wallet_output::LightweightOutputType::Payment => 0,
                    crate::data_structures::wallet_output::LightweightOutputType::Coinbase => 1,
                    crate::data_structures::wallet_output::LightweightOutputType::Burn => 2,
                    crate::data_structures::wallet_output::LightweightOutputType::ValidatorNodeRegistration => 3,
                    crate::data_structures::wallet_output::LightweightOutputType::CodeTemplateRegistration => 4,
                },
                features_json: serde_json::to_string(&output.features)
                    .map_err(|e| LightweightWalletError::InternalError(format!("Failed to serialize features: {}", e)))?,
                maturity: output.features.maturity,
                script_lock_height: output.script_lock_height,
                sender_offset_public_key: output.sender_offset_public_key.as_bytes().to_vec(),
                metadata_signature_ephemeral_commitment: output.metadata_signature.bytes.clone(),
                metadata_signature_ephemeral_pubkey: vec![], // Not available in lightweight format
                metadata_signature_u_a: vec![], // Not available in lightweight format
                metadata_signature_u_x: vec![], // Not available in lightweight format
                metadata_signature_u_y: vec![], // Not available in lightweight format
                encrypted_data: output.encrypted_data.to_byte_vec(),
                minimum_value_promise: output.minimum_value_promise.as_u64(),
                rangeproof: output.range_proof.as_ref().map(|rp| rp.bytes.clone()),
                status: 0, // Unspent by default
                mined_height: None,
                spent_in_tx_id: None,
                created_at: None,
                updated_at: None,
            })
        }
    }

    #[async_trait(?Send)]
    impl StorageManager for BackgroundWriterAdapter {
        async fn save_scan_results(&mut self, results: &ScanResults) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveScanResults {
                results: results.clone(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn save_wallet_output(&mut self, wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveWalletOutput {
                wallet_id,
                output: output.clone(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn save_wallet_outputs(&mut self, wallet_id: u32, outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveWalletOutputs {
                wallet_id,
                outputs: outputs.to_vec(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn save_wallet_state(&mut self, wallet_id: u32, state: &WalletState) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveWalletState {
                wallet_id,
                state: state.clone(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn mark_output_spent(&mut self, commitment: &[u8], block_height: u64) -> LightweightWalletResult<()> {
            let command = StorageCommand::MarkOutputSpent {
                commitment: commitment.to_vec(),
                block_height,
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn get_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState> {
            self.storage.load_wallet_state(wallet_id).await
        }
        
        async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()> {
            let command = StorageCommand::UpdateScannedBlock {
                wallet_id,
                block_height,
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>> {
            let wallet = self.storage.get_wallet_by_id(wallet_id).await?;
            Ok(wallet.and_then(|w| w.latest_scanned_block))
        }
    }

    /// Direct storage adapter for immediate writes (suitable for WASM and low-latency scenarios)
    pub struct DirectStorageAdapter {
        /// Direct reference to storage backend
        storage: Arc<dyn WalletStorage>,
    }

    impl DirectStorageAdapter {
        /// Create a new direct storage adapter
        pub fn new(storage: Arc<dyn WalletStorage>) -> Self {
            Self { storage }
        }
    }

    #[async_trait(?Send)]
    impl StorageManager for DirectStorageAdapter {
        async fn save_scan_results(&mut self, results: &ScanResults) -> LightweightWalletResult<()> {
            BackgroundWriterAdapter::handle_save_scan_results(&*self.storage, results).await
        }
        
        async fn save_wallet_output(&mut self, wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<()> {
            BackgroundWriterAdapter::handle_save_wallet_output(&*self.storage, wallet_id, output).await
        }
        
        async fn save_wallet_outputs(&mut self, wallet_id: u32, outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()> {
            BackgroundWriterAdapter::handle_save_wallet_outputs(&*self.storage, wallet_id, outputs).await
        }
        
        async fn save_wallet_state(&mut self, wallet_id: u32, state: &WalletState) -> LightweightWalletResult<()> {
            BackgroundWriterAdapter::handle_save_wallet_state(&*self.storage, wallet_id, state).await
        }
        
        async fn mark_output_spent(&mut self, commitment: &[u8], block_height: u64) -> LightweightWalletResult<()> {
            BackgroundWriterAdapter::handle_mark_output_spent(&*self.storage, commitment, block_height).await
        }
        
        async fn get_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState> {
            self.storage.load_wallet_state(wallet_id).await
        }
        
        async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()> {
            self.storage.update_wallet_scanned_block(wallet_id, block_height).await
        }
        
        async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>> {
            let wallet = self.storage.get_wallet_by_id(wallet_id).await?;
            Ok(wallet.and_then(|w| w.latest_scanned_block))
        }
    }

    /// Statistics tracking for the background writer
    #[derive(Debug, Default)]
    struct WriterStats {
        operations_count: std::collections::HashMap<String, u64>,
        total_time: std::collections::HashMap<String, Duration>,
    }

    impl WriterStats {
        fn record_operation(&mut self, operation: &str, duration: Duration) {
            *self.operations_count.entry(operation.to_string()).or_insert(0) += 1;
            *self.total_time.entry(operation.to_string()).or_insert(Duration::ZERO) += duration;
        }
    }

    /// Builder for creating storage managers
    pub struct StorageManagerBuilder {
        storage: Option<Arc<dyn WalletStorage>>,
        use_background_writer: bool,
    }

    impl StorageManagerBuilder {
        /// Create a new storage manager builder
        pub fn new() -> Self {
            Self {
                storage: None,
                use_background_writer: true,
            }
        }
        
        /// Set the underlying storage backend
        pub fn with_storage(mut self, storage: Arc<dyn WalletStorage>) -> Self {
            self.storage = Some(storage);
            self
        }
        
        /// Configure whether to use background writer (default: true for native, false for WASM)
        pub fn with_background_writer(mut self, enabled: bool) -> Self {
            self.use_background_writer = enabled;
            self
        }
        
        /// Build the storage manager
        pub fn build(self) -> LightweightWalletResult<Box<dyn StorageManager>> {
            let storage = self.storage.ok_or_else(|| {
                LightweightWalletError::ConfigurationError("Storage backend is required".to_string())
            })?;
            
            if self.use_background_writer {
                Ok(Box::new(BackgroundWriterAdapter::new(storage)))
            } else {
                Ok(Box::new(DirectStorageAdapter::new(storage)))
            }
        }
    }

    impl Default for StorageManagerBuilder {
        fn default() -> Self {
            Self::new()
        }
    }
}

// Re-export storage adapters when storage feature is enabled
#[cfg(feature = "storage")]
pub use storage_adapters::{BackgroundWriterAdapter, DirectStorageAdapter, StorageManagerBuilder};

#[cfg(all(test, feature = "storage", not(target_arch = "wasm32")))]
mod tests {
    #[cfg(feature = "storage")]
    use super::*;
    
    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_mock_storage_manager() {
        let mut manager = MockStorageManager::new();
        
        // Test update and get scanned block
        manager.update_scanned_block(1, 1000).await.unwrap();
        let block = manager.get_latest_scanned_block(1).await.unwrap();
        assert_eq!(block, Some(1000));
        
        // Test non-existent wallet
        let block = manager.get_latest_scanned_block(999).await.unwrap();
        assert_eq!(block, None);
    }
    
    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_storage_manager_builder() {
        use crate::storage::sqlite::SqliteStorage;
        use crate::storage::WalletStorage;
        use tempfile::NamedTempFile;
        
        let temp_file = NamedTempFile::new().unwrap();
        let storage = std::sync::Arc::new(SqliteStorage::new(temp_file.path().to_str().unwrap()).await.unwrap());
        
        // Initialize the storage (create tables)
        storage.initialize().await.unwrap();
        
        let manager = StorageManagerBuilder::new()
            .with_storage(storage)
            .with_background_writer(false)
            .build()
            .unwrap();
            
        let result = manager.get_latest_scanned_block(1).await;
        // Should return None for non-existent wallet, not an error
        assert_eq!(result.unwrap(), None);
    }
}
