use serde::{Deserialize, Serialize};
use tari_transaction_components::{
    key_manager::{TariKeyId, TransactionKeyManagerInterface},
    transaction_components::WalletOutput,
};
use tari_utilities::hex::{from_hex, Hex};

use crate::{KeyManagementError, WalletError};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OutputPair {
    pub output: WalletOutput,
    pub kernel_nonce: TariKeyId,
    pub sender_offset_key_id: Option<TariKeyId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MarshalOutputPair {
    pub output_pair: OutputPair,
    pub encrypted_kernel_nonce: String,
    pub encrypted_sender_offset_key: Option<String>,
    pub encrypted_output_commitment_mask: String,
}

impl MarshalOutputPair {
    pub async fn marshal<KM: TransactionKeyManagerInterface>(
        key_manager: &KM,
        output_pair: OutputPair,
    ) -> Result<Self, WalletError> {
        let encrypted_kernel_nonce =
            MarshalOutputPair::encrypt_key(key_manager, &output_pair.kernel_nonce).await?;
        let encrypted_sender_offset_key = match &output_pair.sender_offset_key_id {
            Some(key) => Some(MarshalOutputPair::encrypt_key(key_manager, key).await?),
            None => None,
        };
        let encrypted_output_commitment_mask =
            MarshalOutputPair::encrypt_key(key_manager, &output_pair.output.spending_key_id)
                .await?;

        Ok(MarshalOutputPair {
            output_pair,
            encrypted_kernel_nonce,
            encrypted_sender_offset_key,
            encrypted_output_commitment_mask,
        })
    }

    pub async fn unmarshal<KM: TransactionKeyManagerInterface>(
        &mut self,
        key_manager: &KM,
    ) -> Result<(), WalletError> {
        self.output_pair.kernel_nonce =
            MarshalOutputPair::import_encrypted_key(key_manager, &self.encrypted_kernel_nonce)
                .await?;
        if let Some(sender_offset_key_id) = &self.encrypted_sender_offset_key {
            self.output_pair.sender_offset_key_id = Some(
                MarshalOutputPair::import_encrypted_key(key_manager, sender_offset_key_id).await?,
            );
        }
        self.output_pair.output.spending_key_id = MarshalOutputPair::import_encrypted_key(
            key_manager,
            &self.encrypted_output_commitment_mask,
        )
        .await?;
        Ok(())
    }

    async fn encrypt_key<KM: TransactionKeyManagerInterface>(
        key_manager: &KM,
        key_id: &TariKeyId,
    ) -> Result<String, WalletError> {
        let encrypted = key_manager.encrypted_key(key_id, None).await?;
        Ok(encrypted.to_hex())
    }

    async fn import_encrypted_key<KM: TransactionKeyManagerInterface>(
        key_manager: &KM,
        encrypted: &str,
    ) -> Result<TariKeyId, WalletError> {
        let encrypted_bytes = from_hex(encrypted)
            .map_err(|err| KeyManagementError::KeyDecryptionError(err.to_string()))?;
        let key_id = key_manager
            .import_encrypted_key(encrypted_bytes, None)
            .await?;
        Ok(key_id)
    }
}
