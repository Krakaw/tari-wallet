#[cfg(feature = "storage")]
use tari_script::TariScript;
#[cfg(feature = "storage")]
use tari_transaction_components::{
    fee::Fee, tari_amount::MicroMinotari, weight::TransactionWeight,
};

#[cfg(feature = "storage")]
use crate::{
    data_structures::{Covenant, OutputFeatures},
    utils::borsh::SerializedSize,
    SerializationError, StoredOutput, WalletError, WalletResult, WalletStorage,
};

#[cfg(feature = "storage")]
struct UtxoSelection {
    utxos: Vec<StoredOutput>,
    requires_change_output: bool,
    total_value: MicroMinotari,
    fee_without_change: MicroMinotari,
    fee_with_change: MicroMinotari,
}

#[cfg(feature = "storage")]
struct InputSelector {
    pub wallet_id: u32,
    #[cfg(feature = "storage")]
    pub database: Box<dyn WalletStorage>,
    pub fee_calc: Fee,
}

#[cfg(feature = "storage")]
impl InputSelector {
    pub fn new(wallet_id: u32, database: Box<dyn WalletStorage>) -> Self {
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
