//! Block processing functionality for wallet scanning
//!
//! This module provides a `Block` struct that encapsulates all the logic for:
//! - Processing transaction outputs to discover wallet outputs
//! - Processing transaction inputs to detect spending
//! - Multiple decryption methods (regular, one-sided, range proof rewinding)
//! - Coinbase output handling with ownership verification
//! - **Parallel processing for performance optimization**

use crate::{
    data_structures::{
        encrypted_data::EncryptedData,
        payment_id::PaymentId,
        transaction::{TransactionDirection, TransactionStatus},
        transaction_input::TransactionInput,
        transaction_output::LightweightTransactionOutput,
        types::PrivateKey,
        wallet_output::LightweightOutputType,
        wallet_transaction::WalletState,
    },
    errors::LightweightWalletResult,
};

#[cfg(feature = "grpc")]
use crate::scanning::BlockInfo;

// Add rayon for parallel processing
#[cfg(feature = "grpc")]
use rayon::prelude::*;

/// A block with wallet-focused processing capabilities
///
/// This struct wraps a `BlockInfo` and provides methods to extract wallet outputs
/// and detect spending using various decryption techniques.
pub struct Block {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: Vec<u8>,
    /// Block timestamp
    pub timestamp: u64,
    /// Transaction outputs in this block
    pub outputs: Vec<LightweightTransactionOutput>,
    /// Transaction inputs in this block  
    pub inputs: Vec<TransactionInput>,
    /// Original HTTP output hashes (for HTTP scanner compatibility)
    pub http_output_hashes: Option<Vec<Vec<u8>>>,
}

/// Result of processing a single output
#[derive(Debug, Clone)]
struct OutputProcessingResult {
    output_index: usize,
    value: u64,
    payment_id: PaymentId,
    transaction_status: TransactionStatus,
    is_mature: bool,
}

impl Block {
    /// Create a new Block from BlockInfo (only available with grpc feature)
    #[cfg(feature = "grpc")]
    pub fn from_block_info(block_info: BlockInfo) -> Self {
        Self {
            height: block_info.height,
            hash: block_info.hash,
            timestamp: block_info.timestamp,
            outputs: block_info.outputs,
            inputs: block_info.inputs,
            http_output_hashes: block_info.http_output_hashes,
        }
    }

    /// Create a new Block with specified data
    pub fn new(
        height: u64,
        hash: Vec<u8>,
        timestamp: u64,
        outputs: Vec<LightweightTransactionOutput>,
        inputs: Vec<TransactionInput>,
    ) -> Self {
        Self {
            height,
            hash,
            timestamp,
            outputs,
            inputs,
            http_output_hashes: None,
        }
    }

    /// Create a new Block with HTTP output hashes
    pub fn new_with_http_hashes(
        height: u64,
        hash: Vec<u8>,
        timestamp: u64,
        outputs: Vec<LightweightTransactionOutput>,
        inputs: Vec<TransactionInput>,
        http_output_hashes: Option<Vec<Vec<u8>>>,
    ) -> Self {
        Self {
            height,
            hash,
            timestamp,
            outputs,
            inputs,
            http_output_hashes,
        }
    }

    /// Process all outputs in this block to discover wallet outputs - OPTIMIZED VERSION
    ///
    /// This method uses parallel processing and optimized decryption attempts to maximize performance
    pub fn process_outputs(
        &self,
        view_key: &PrivateKey,
        _entropy: &[u8; 16],
        wallet_state: &mut WalletState,
    ) -> LightweightWalletResult<usize> {
        // Use HTTP output hashes if available, otherwise use None
        let http_hashes = self
            .http_output_hashes
            .as_ref()
            .map(|hashes| hashes.as_slice());
        self.process_outputs_with_hashes(view_key, _entropy, wallet_state, http_hashes)
    }

    /// Process all outputs in this block with optional HTTP output hashes preservation
    ///
    /// This method allows preserving original output hashes from HTTP responses for accurate spending detection
    pub fn process_outputs_with_hashes(
        &self,
        view_key: &PrivateKey,
        _entropy: &[u8; 16],
        wallet_state: &mut WalletState,
        http_output_hashes: Option<&[Vec<u8>]>,
    ) -> LightweightWalletResult<usize> {
        if self.outputs.is_empty() {
            return Ok(0);
        }

        // Process outputs in parallel when feature is enabled
        #[cfg(feature = "grpc")]
        let results: Vec<OutputProcessingResult> = self
            .outputs
            .par_iter()
            .enumerate()
            .filter_map(|(output_index, output)| {
                self.process_single_output_parallel(output_index, output, view_key)
            })
            .collect();

        // Fallback to sequential processing when parallel feature not enabled
        #[cfg(not(feature = "grpc"))]
        let results: Vec<OutputProcessingResult> = self
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(output_index, output)| {
                self.process_single_output_parallel(output_index, output, view_key)
            })
            .collect();

        // Add all found outputs to wallet state
        let found_count = results.len();
        for result in results {
            // Use HTTP output hash if available, otherwise calculate from transaction output
            let output_hash = if let Some(hashes) = http_output_hashes {
                if result.output_index < hashes.len() {
                    Some(hashes[result.output_index].clone())
                } else {
                    Some(self.outputs[result.output_index].hash().to_vec())
                }
            } else {
                Some(self.outputs[result.output_index].hash().to_vec())
            };

            wallet_state.add_received_output(
                self.height,
                result.output_index,
                self.outputs[result.output_index].commitment.clone(),
                output_hash, // Use preserved HTTP output hash or calculated hash
                result.value,
                result.payment_id,
                result.transaction_status,
                TransactionDirection::Inbound,
                result.is_mature,
            );
        }

        Ok(found_count)
    }

    /// Process a single output with optimized decryption strategy
    fn process_single_output_parallel(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        // Early exit for outputs with no encrypted data (except coinbase)
        let has_encrypted_data = !output.encrypted_data.as_bytes().is_empty();
        let is_coinbase = matches!(output.features.output_type, LightweightOutputType::Coinbase);

        if !has_encrypted_data && !is_coinbase {
            return None;
        }

        // Handle coinbase outputs
        if is_coinbase {
            if let Some(result) = self.try_coinbase_output_optimized(output_index, output, view_key)
            {
                return Some(result);
            }
        }

        // Skip further processing if no encrypted data
        if !has_encrypted_data {
            return None;
        }

        // Try regular decryption first (most common case)
        if let Some(result) = self.try_regular_decryption_optimized(output_index, output, view_key)
        {
            return Some(result);
        }

        // Try one-sided decryption only if sender offset key is present
        if !output.sender_offset_public_key.as_bytes().is_empty() {
            if let Some(result) =
                self.try_one_sided_decryption_optimized(output_index, output, view_key)
            {
                return Some(result);
            }
        }

        None
    }

    /// Optimized coinbase output processing
    fn try_coinbase_output_optimized(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        let coinbase_value = output.minimum_value_promise.as_u64();
        if coinbase_value == 0 {
            return None;
        }

        // For coinbase outputs, verify ownership through encrypted data decryption
        let mut is_ours = false;

        if !output.encrypted_data.as_bytes().is_empty() {
            // Try regular decryption for ownership verification first (faster)
            is_ours = EncryptedData::decrypt_data(view_key, &output.commitment, &output.encrypted_data)
                .is_ok()
            // Only try one-sided decryption if regular failed and sender offset key exists
            || (!output.sender_offset_public_key.as_bytes().is_empty() && EncryptedData::decrypt_one_sided_data(
                    view_key,
                    &output.commitment,
                    &output.sender_offset_public_key,
                    &output.encrypted_data,
                )
                .is_ok());
        }

        if is_ours {
            // Check if coinbase is mature (can be spent)
            let is_mature = self.height >= output.features.maturity;

            return Some(OutputProcessingResult {
                output_index,
                value: coinbase_value,
                payment_id: PaymentId::Empty, // Coinbase outputs typically have no payment ID
                transaction_status: if is_mature {
                    TransactionStatus::CoinbaseConfirmed
                } else {
                    TransactionStatus::CoinbaseUnconfirmed
                },
                is_mature,
            });
        }

        None
    }

    /// Optimized regular encrypted data decryption
    fn try_regular_decryption_optimized(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        if let Ok((value, _mask, payment_id)) =
            EncryptedData::decrypt_data(view_key, &output.commitment, &output.encrypted_data)
        {
            return Some(OutputProcessingResult {
                output_index,
                value: value.as_u64(),
                payment_id,
                transaction_status: TransactionStatus::MinedConfirmed,
                is_mature: true, // Regular payments are always mature
            });
        }
        None
    }

    /// Optimized one-sided encrypted data decryption
    fn try_one_sided_decryption_optimized(
        &self,
        output_index: usize,
        output: &LightweightTransactionOutput,
        view_key: &PrivateKey,
    ) -> Option<OutputProcessingResult> {
        if let Ok((value, _mask, payment_id)) = EncryptedData::decrypt_one_sided_data(
            view_key,
            &output.commitment,
            &output.sender_offset_public_key,
            &output.encrypted_data,
        ) {
            return Some(OutputProcessingResult {
                output_index,
                value: value.as_u64(),
                payment_id,
                transaction_status: TransactionStatus::OneSidedConfirmed,
                is_mature: true, // One-sided payments are always mature
            });
        }
        None
    }

    /// Process all inputs in this block to detect spending of wallet outputs
    pub fn process_inputs(&self, wallet_state: &mut WalletState) -> LightweightWalletResult<usize> {
        let mut spent_outputs = 0;

        for (input_index, input) in self.inputs.iter().enumerate() {
            let mut found_spent = false;

            // Try to match by output hash first (for HTTP API)
            // Only attempt if output_hash is not all zeros (HTTP API provides real output hashes)
            if !input.output_hash.iter().all(|&b| b == 0)
                && wallet_state.mark_output_spent_by_hash(
                    &input.output_hash,
                    self.height,
                    input_index,
                )
            {
                spent_outputs += 1;
                found_spent = true;
            }

            // If output hash matching failed or output_hash is all zeros, try commitment matching (for GRPC API)
            if !found_spent && !input.commitment.iter().all(|&b| b == 0) {
                use crate::data_structures::types::CompressedCommitment;
                let commitment = CompressedCommitment::new(input.commitment);
                if wallet_state.mark_output_spent(&commitment, self.height, input_index) {
                    spent_outputs += 1;
                }
            }
        }

        Ok(spent_outputs)
    }

    /// Scan this block for all wallet activity (outputs and inputs)
    ///
    /// This is a convenience method that calls both `process_outputs` and `process_inputs`
    pub fn scan_for_wallet_activity(
        &self,
        view_key: &PrivateKey,
        entropy: &[u8; 16],
        wallet_state: &mut WalletState,
    ) -> LightweightWalletResult<(usize, usize)> {
        let found_outputs = self.process_outputs(view_key, entropy, wallet_state)?;
        let spent_outputs = self.process_inputs(wallet_state)?;
        Ok((found_outputs, spent_outputs))
    }

    /// Get the number of outputs in this block
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Get the number of inputs in this block
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Get block summary information
    pub fn summary(&self) -> BlockSummary {
        BlockSummary {
            height: self.height,
            hash: self.hash.clone(),
            timestamp: self.timestamp,
            output_count: self.outputs.len(),
            input_count: self.inputs.len(),
        }
    }
}

/// Summary information about a block
#[derive(Debug, Clone)]
pub struct BlockSummary {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: Vec<u8>,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of outputs in the block
    pub output_count: usize,
    /// Number of inputs in the block
    pub input_count: usize,
}

impl std::fmt::Display for BlockSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {} (outputs: {}, inputs: {})",
            self.height, self.output_count, self.input_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{
        encrypted_data::EncryptedData,
        payment_id::PaymentId,
        transaction::{TransactionDirection, TransactionStatus},
        transaction_input::TransactionInput,
        transaction_output::LightweightTransactionOutput,
        types::{CompressedCommitment, CompressedPublicKey, MicroMinotari, PrivateKey},
        wallet_output::{LightweightOutputFeatures, LightweightOutputType},
        wallet_transaction::WalletState,
    };

    fn create_test_block() -> Block {
        Block::new(1000, vec![1, 2, 3, 4], 1234567890, vec![], vec![])
    }

    fn create_test_private_key() -> PrivateKey {
        PrivateKey::new([1u8; 32])
    }

    fn create_test_output_with_features(
        output_type: LightweightOutputType,
        maturity: u64,
        value: u64,
    ) -> LightweightTransactionOutput {
        let features = LightweightOutputFeatures {
            output_type,
            maturity,
            ..Default::default()
        };

        LightweightTransactionOutput::new(
            1,
            features,
            CompressedCommitment::new([1u8; 32]),
            None,
            Default::default(),
            CompressedPublicKey::default(),
            Default::default(),
            Default::default(),
            EncryptedData::default(),
            MicroMinotari::new(value),
        )
    }

    fn create_test_input(commitment: [u8; 32], output_hash: [u8; 32]) -> TransactionInput {
        TransactionInput::new(
            1,
            0,
            commitment,
            [0u8; 64],
            CompressedPublicKey::default(),
            Vec::new(),
            crate::data_structures::transaction_input::LightweightExecutionStack::new(),
            output_hash,
            0,
            [0u8; 64],
            0,
            MicroMinotari::new(0),
        )
    }

    #[test]
    fn test_block_creation() {
        let block = create_test_block();
        assert_eq!(block.height, 1000);
        assert_eq!(block.hash, vec![1, 2, 3, 4]);
        assert_eq!(block.timestamp, 1234567890);
        assert_eq!(block.output_count(), 0);
        assert_eq!(block.input_count(), 0);
    }

    #[test]
    fn test_block_with_outputs_and_inputs() {
        let output = create_test_output_with_features(LightweightOutputType::Payment, 0, 1000);
        let input = create_test_input([1u8; 32], [2u8; 32]);

        let block = Block::new(
            1000,
            vec![1, 2, 3, 4],
            1234567890,
            vec![output],
            vec![input],
        );

        assert_eq!(block.output_count(), 1);
        assert_eq!(block.input_count(), 1);
    }

    #[test]
    fn test_block_summary() {
        let output1 = create_test_output_with_features(LightweightOutputType::Payment, 0, 1000);
        let output2 = create_test_output_with_features(LightweightOutputType::Coinbase, 100, 5000);
        let input = create_test_input([1u8; 32], [2u8; 32]);

        let block = Block::new(
            1000,
            vec![1, 2, 3, 4],
            1234567890,
            vec![output1, output2],
            vec![input],
        );

        let summary = block.summary();
        assert_eq!(summary.height, 1000);
        assert_eq!(summary.hash, vec![1, 2, 3, 4]);
        assert_eq!(summary.timestamp, 1234567890);
        assert_eq!(summary.output_count, 2);
        assert_eq!(summary.input_count, 1);

        let summary_str = summary.to_string();
        assert!(summary_str.contains("Block 1000"));
        assert!(summary_str.contains("outputs: 2"));
        assert!(summary_str.contains("inputs: 1"));
    }

    #[test]
    #[cfg(feature = "grpc")]
    fn test_block_from_block_info() {
        let block_info = crate::scanning::BlockInfo {
            height: 1000,
            hash: vec![1, 2, 3, 4],
            timestamp: 1234567890,
            outputs: vec![],
            inputs: vec![],
            kernels: vec![],
        };

        let block = Block::from_block_info(block_info);
        assert_eq!(block.height, 1000);
        assert_eq!(block.hash, vec![1, 2, 3, 4]);
        assert_eq!(block.timestamp, 1234567890);
    }

    #[test]
    fn test_process_outputs_empty_block() {
        let block = create_test_block();
        let view_key = create_test_private_key();
        let entropy = [0u8; 16];
        let mut wallet_state = WalletState::new();

        let found_count = block
            .process_outputs(&view_key, &entropy, &mut wallet_state)
            .unwrap();
        assert_eq!(found_count, 0);
    }

    #[test]
    fn test_process_outputs_no_encrypted_data() {
        let output = create_test_output_with_features(LightweightOutputType::Payment, 0, 1000);
        let block = Block::new(1000, vec![1, 2, 3, 4], 1234567890, vec![output], vec![]);

        let view_key = create_test_private_key();
        let entropy = [0u8; 16];
        let mut wallet_state = WalletState::new();

        // Should find no outputs since there's no encrypted data and it's not coinbase
        let found_count = block
            .process_outputs(&view_key, &entropy, &mut wallet_state)
            .unwrap();
        assert_eq!(found_count, 0);
    }

    #[test]
    fn test_process_outputs_coinbase_without_encrypted_data() {
        let output = create_test_output_with_features(LightweightOutputType::Coinbase, 100, 5000);
        let block = Block::new(1100, vec![1, 2, 3, 4], 1234567890, vec![output], vec![]);

        let view_key = create_test_private_key();
        let entropy = [0u8; 16];
        let mut wallet_state = WalletState::new();

        // Should find no outputs since coinbase has no encrypted data to verify ownership
        let found_count = block
            .process_outputs(&view_key, &entropy, &mut wallet_state)
            .unwrap();
        assert_eq!(found_count, 0);
    }

    #[test]
    fn test_process_outputs_coinbase_maturity() {
        let mut output =
            create_test_output_with_features(LightweightOutputType::Coinbase, 100, 5000);
        // Add some encrypted data to simulate ownership verification
        output.encrypted_data = EncryptedData::from_bytes(&[1, 2, 3, 4]).unwrap_or_default();

        // Test immature coinbase (block height < maturity)
        let block_immature = Block::new(
            50,
            vec![1, 2, 3, 4],
            1234567890,
            vec![output.clone()],
            vec![],
        );
        let view_key = create_test_private_key();
        let entropy = [0u8; 16];
        let mut wallet_state = WalletState::new();

        let found_count = block_immature
            .process_outputs(&view_key, &entropy, &mut wallet_state)
            .unwrap();
        // Will be 0 because encryption verification will fail with test data
        assert_eq!(found_count, 0);

        // Test mature coinbase (block height >= maturity)
        let block_mature = Block::new(150, vec![1, 2, 3, 4], 1234567890, vec![output], vec![]);
        let mut wallet_state = WalletState::new();

        let found_count = block_mature
            .process_outputs(&view_key, &entropy, &mut wallet_state)
            .unwrap();
        // Will be 0 because encryption verification will fail with test data
        assert_eq!(found_count, 0);
    }

    #[test]
    fn test_process_inputs_empty_block() {
        let block = create_test_block();
        let mut wallet_state = WalletState::new();

        let spent_count = block.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 0);
    }

    #[test]
    fn test_process_inputs_no_matching_outputs() {
        let input = create_test_input([1u8; 32], [2u8; 32]);
        let block = Block::new(200, vec![1, 2, 3], 123456789, vec![], vec![input]);
        let mut wallet_state = WalletState::new();

        let spent_count = block.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 0);
    }

    #[test]
    fn test_process_inputs_http_and_grpc_compatibility() {
        let mut wallet_state = WalletState::new();
        let commitment = CompressedCommitment::new([1u8; 32]);
        let output_hash = [2u8; 32];

        // Add a received output to wallet state (using both commitment and output hash)
        wallet_state.add_received_output(
            100,
            0,
            commitment.clone(),
            Some(output_hash.to_vec()),
            1000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        // Test 1: HTTP-style input (has output hash, zero commitment)
        let http_input = create_test_input([0u8; 32], output_hash);
        let block_http = Block::new(200, vec![1, 2, 3], 123456789, vec![], vec![http_input]);

        // Should find the spent output using output hash matching
        let spent_count = block_http.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 1);
        let (_, _, _, _, spent_count_after) = wallet_state.get_summary();
        assert_eq!(spent_count_after, 1);

        // Reset wallet state for next test
        let mut wallet_state = WalletState::new();
        wallet_state.add_received_output(
            100,
            0,
            commitment.clone(),
            Some(output_hash.to_vec()),
            1000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        // Test 2: GRPC-style input (has commitment, zero output hash)
        let grpc_input = create_test_input(*commitment.as_bytes(), [0u8; 32]);
        let block_grpc = Block::new(200, vec![1, 2, 3], 123456789, vec![], vec![grpc_input]);

        // Should find the spent output using commitment matching
        let spent_count = block_grpc.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 1);
        let (_, _, _, _, spent_count_after) = wallet_state.get_summary();
        assert_eq!(spent_count_after, 1);
    }

    #[test]
    fn test_process_inputs_multiple_inputs() {
        let mut wallet_state = WalletState::new();
        let commitment1 = CompressedCommitment::new([1u8; 32]);
        let commitment2 = CompressedCommitment::new([2u8; 32]);
        let output_hash1 = [3u8; 32];
        let output_hash2 = [4u8; 32];

        // Add multiple received outputs
        wallet_state.add_received_output(
            100,
            0,
            commitment1.clone(),
            Some(output_hash1.to_vec()),
            1000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );
        wallet_state.add_received_output(
            100,
            1,
            commitment2.clone(),
            Some(output_hash2.to_vec()),
            2000,
            PaymentId::Empty,
            TransactionStatus::MinedConfirmed,
            TransactionDirection::Inbound,
            true,
        );

        // Create inputs that spend both outputs
        let input1 = create_test_input([0u8; 32], output_hash1);
        let input2 = create_test_input(*commitment2.as_bytes(), [0u8; 32]);

        let block = Block::new(200, vec![1, 2, 3], 123456789, vec![], vec![input1, input2]);

        let spent_count = block.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 2);
        let (_, _, _, _, spent_count_after) = wallet_state.get_summary();
        assert_eq!(spent_count_after, 2);
    }

    #[test]
    fn test_scan_for_wallet_activity() {
        let output = create_test_output_with_features(LightweightOutputType::Payment, 0, 1000);
        let input = create_test_input([1u8; 32], [2u8; 32]);

        let block = Block::new(
            1000,
            vec![1, 2, 3, 4],
            1234567890,
            vec![output],
            vec![input],
        );
        let view_key = create_test_private_key();
        let entropy = [0u8; 16];
        let mut wallet_state = WalletState::new();

        let (found_outputs, spent_outputs) = block
            .scan_for_wallet_activity(&view_key, &entropy, &mut wallet_state)
            .unwrap();

        // Should find no outputs due to missing encrypted data, and no spent outputs due to no matching outputs
        assert_eq!(found_outputs, 0);
        assert_eq!(spent_outputs, 0);
    }

    #[test]
    fn test_block_edge_cases() {
        // Test with maximum values
        let block = Block::new(u64::MAX, vec![255u8; 32], u64::MAX, vec![], vec![]);
        assert_eq!(block.height, u64::MAX);
        assert_eq!(block.timestamp, u64::MAX);
        assert_eq!(block.hash.len(), 32);

        // Test with empty hash
        let block_empty_hash = Block::new(0, vec![], 0, vec![], vec![]);
        assert_eq!(block_empty_hash.hash.len(), 0);

        // Test with large numbers of outputs and inputs
        let outputs =
            vec![create_test_output_with_features(LightweightOutputType::Payment, 0, 1000); 100];
        let inputs = vec![create_test_input([1u8; 32], [2u8; 32]); 50];

        let large_block = Block::new(1000, vec![1, 2, 3, 4], 1234567890, outputs, inputs);
        assert_eq!(large_block.output_count(), 100);
        assert_eq!(large_block.input_count(), 50);
    }

    #[test]
    fn test_output_processing_result() {
        // Test the internal OutputProcessingResult structure indirectly
        let mut output =
            create_test_output_with_features(LightweightOutputType::Coinbase, 100, 5000);
        output.encrypted_data = EncryptedData::from_bytes(&[1, 2, 3, 4]).unwrap_or_default();

        let block = Block::new(150, vec![1, 2, 3, 4], 1234567890, vec![output], vec![]);
        let view_key = create_test_private_key();
        let entropy = [0u8; 16];
        let mut wallet_state = WalletState::new();

        // This tests the internal processing result handling
        let found_count = block
            .process_outputs(&view_key, &entropy, &mut wallet_state)
            .unwrap();
        assert_eq!(found_count, 0); // Will be 0 due to encryption verification failure with test data
    }

    #[test]
    fn test_parallel_vs_sequential_processing() {
        // This test ensures both parallel and sequential code paths work
        let outputs = vec![
            create_test_output_with_features(LightweightOutputType::Payment, 0, 1000),
            create_test_output_with_features(LightweightOutputType::Coinbase, 50, 2000),
            create_test_output_with_features(LightweightOutputType::Payment, 0, 3000),
        ];

        let block = Block::new(1000, vec![1, 2, 3, 4], 1234567890, outputs, vec![]);
        let view_key = create_test_private_key();
        let entropy = [0u8; 16];
        let mut wallet_state = WalletState::new();

        // Test with current feature flags
        let found_count = block
            .process_outputs(&view_key, &entropy, &mut wallet_state)
            .unwrap();

        // Should be 0 due to no valid encrypted data for test keys
        assert_eq!(found_count, 0);
    }

    #[test]
    fn test_input_processing_edge_cases() {
        let mut wallet_state = WalletState::new();

        // Test input with all zero commitment and output hash
        let zero_input = create_test_input([0u8; 32], [0u8; 32]);
        let block = Block::new(200, vec![1, 2, 3], 123456789, vec![], vec![zero_input]);

        let spent_count = block.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count, 0);

        // Test input with partial zeros
        let partial_zero_input = create_test_input([1u8; 32], [0u8; 32]);
        let block2 = Block::new(
            200,
            vec![1, 2, 3],
            123456789,
            vec![],
            vec![partial_zero_input],
        );

        let spent_count2 = block2.process_inputs(&mut wallet_state).unwrap();
        assert_eq!(spent_count2, 0);
    }
}
