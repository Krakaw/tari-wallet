use std::sync::Arc;

use tari_script::TariScript;
use tari_transaction_components::{
    fee::Fee, helpers::borsh::SerializedSize, tari_amount::MicroMinotari, weight::TransactionWeight,
};

use crate::{
    data_structures::{Covenant, OutputFeatures},
    SerializationError, StoredOutput, WalletError, WalletResult, WalletStorage,
};

#[derive(Debug)]
pub struct UtxoSelection {
    pub utxos: Vec<StoredOutput>,
    pub requires_change_output: bool,
    pub total_value: MicroMinotari,
    pub fee_without_change: MicroMinotari,
    pub fee_with_change: MicroMinotari,
}

impl UtxoSelection {
    pub fn fee(&self) -> MicroMinotari {
        if self.requires_change_output {
            self.fee_with_change
        } else {
            self.fee_without_change
        }
    }
}

pub struct InputSelector {
    pub wallet_id: u32,
    pub database: Arc<dyn WalletStorage>,
    pub fee_calc: Fee,
}

impl InputSelector {
    pub fn new(wallet_id: u32, database: Arc<dyn WalletStorage>) -> Self {
        Self {
            wallet_id,
            database,
            fee_calc: Fee::new(TransactionWeight::latest()),
        }
    }

    fn get_features_and_scripts_byte_size(&self) -> WalletResult<usize> {
        let output_features_size = OutputFeatures::default()
            .get_serialized_size()
            .map_err(|e| SerializationError::BorshSerializationError(e.to_string()))?;
        let tari_script_size = TariScript::default()
            .get_serialized_size()
            .map_err(|e| SerializationError::BorshSerializationError(e.to_string()))?;
        let covenant_size = Covenant::default()
            .get_serialized_size()
            .map_err(|e| SerializationError::BorshSerializationError(e.to_string()))?;

        Ok(self
            .fee_calc
            .weighting()
            .round_up_features_and_scripts_size(
                output_features_size + tari_script_size + covenant_size,
            ))
    }

    pub async fn fetch_unspent_outputs(
        &self,
        amount: MicroMinotari,
        fee_per_gram: MicroMinotari,
    ) -> WalletResult<UtxoSelection> {
        let mut uo = self.database.get_unspent_outputs(self.wallet_id).await?;
        uo.sort_by(|a, b| a.value.cmp(&b.value));

        let features_and_scripts_byte_size = self.get_features_and_scripts_byte_size()?;

        let mut sufficient_funds = false;
        let mut utxos = Vec::new();
        let mut requires_change_output = false;
        let mut total_value = MicroMinotari::zero();
        let mut fee_without_change = MicroMinotari::zero();
        let mut fee_with_change = MicroMinotari::zero();
        // Planned output count (not counting change)
        let num_outputs = 1;

        for o in uo {
            total_value += MicroMinotari::from(o.value);
            utxos.push(o);

            fee_without_change = self.fee_calc.calculate(
                fee_per_gram,
                1,
                utxos.len(),
                num_outputs,
                features_and_scripts_byte_size,
            );
            if total_value == amount + fee_without_change {
                sufficient_funds = true;
                break;
            }
            fee_with_change = self.fee_calc.calculate(
                fee_per_gram,
                1,
                utxos.len(),
                num_outputs + 1,
                2 * features_and_scripts_byte_size,
            );

            if total_value > amount + fee_with_change {
                sufficient_funds = true;
                requires_change_output = true;
                break;
            }
        }

        if !sufficient_funds {
            return Err(WalletError::InsufficientFunds(format!(
                "Not enough funds. Available: {total_value}, required: {}",
                amount + fee_with_change
            )));
        }

        Ok(UtxoSelection {
            utxos,
            requires_change_output,
            total_value,
            fee_without_change,
            fee_with_change,
        })
    }
}
