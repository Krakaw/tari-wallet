use tari_transaction_components::transaction_components::{
    CoinBaseExtra, OutputFeatures, OutputFeaturesVersion, OutputType, RangeProofType,
};

use crate::tari_rpc;

pub fn convert_output_features(features: tari_rpc::OutputFeatures) -> OutputFeatures {
    let version = OutputFeaturesVersion::try_from(u8::try_from(features.version).unwrap()).unwrap();
    let output_type = OutputType::from_byte(u8::try_from(features.output_type).unwrap()).unwrap();
    let coinbase_extra = CoinBaseExtra::try_from(features.coinbase_extra).unwrap();
    let sidechain_feature = match features.sidechain_feature {
        Some(_) => panic!("Cannot deserialize sidechain features!"),
        None => None,
    };
    let range_proof_type =
        RangeProofType::from_byte(u8::try_from(features.range_proof_type).unwrap()).unwrap();

    OutputFeatures::new(
        version,
        output_type,
        features.maturity,
        coinbase_extra,
        sidechain_feature,
        range_proof_type,
    )
}
