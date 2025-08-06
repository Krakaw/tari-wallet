use std::str::FromStr;
use tari_common_types::types::CompressedPublicKey;
use tari_transaction_components::key_manager::{TariKeyId, TransactionKeyManagerInterface};

use crate::key_manager::TransactionKeyManager;

pub async fn make_key_id_export_safe(
    transaction_key_manager: &TransactionKeyManager,
    key_id: &TariKeyId,
) -> Result<TariKeyId, String> {
    if *key_id
        == transaction_key_manager
            .get_spend_key()
            .await
            .map_err(|err| err.to_string())?
            .key_id
    {
        return Ok(key_id.clone());
    }
    if *key_id
        == transaction_key_manager
            .get_view_key()
            .await
            .map_err(|err| err.to_string())?
            .key_id
    {
        return Ok(key_id.clone());
    }

    match key_id {
        TariKeyId::Zero => Ok(TariKeyId::Zero),
        TariKeyId::Imported { .. } => {
            // This is an imported key, so we can safely export it
            Ok(key_id.clone())
        }
        TariKeyId::Derived { key } => {
            let inner_key = TariKeyId::from_str(key.to_string().as_str())?;
            let public_key = transaction_key_manager
                .get_public_key_at_key_id(&inner_key)
                .await
                .map_err(|err| err.to_string())?;
            let modified_key = TariKeyId::Imported {
                key: CompressedPublicKey::new_from_pk(
                    public_key.to_public_key().map_err(|err| err.to_string())?,
                ),
            };
            let key = TariKeyId::Derived {
                key: modified_key.into(),
            };
            Ok(key)
        }
        TariKeyId::Managed { .. } => {
            let key = transaction_key_manager
                .get_public_key_at_key_id(key_id)
                .await
                .map_err(|err| err.to_string())?;

            Ok(TariKeyId::Imported {
                key: CompressedPublicKey::new_from_pk(
                    key.to_public_key().map_err(|err| err.to_string())?,
                ),
            })
        }
    }
}
