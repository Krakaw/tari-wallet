use borsh::BorshSerialize;
use tari_common_types::{
    payment_reference::generate_payment_reference,
    types::{BlockHash, CompressedSignature},
};
use tari_crypto::tari_utilities::ByteArray;
use tari_transaction_components::{
    aggregated_body::AggregateBody,
    transaction_components::{
        OutputFeatures, SideChainFeature, SideChainFeatureData, SideChainId, Transaction,
        TransactionInput, TransactionKernel, TransactionOutput,
    },
};

use crate::tari_rpc;

fn convert_sidechain_feature_data(
    _data: SideChainFeatureData,
) -> tari_rpc::side_chain_feature::Feature {
    unimplemented!()
}

fn convert_signature(signature: CompressedSignature) -> tari_rpc::Signature {
    tari_rpc::Signature {
        public_nonce: signature.get_compressed_public_nonce().to_vec(),
        signature: signature.get_signature().to_vec(),
    }
}

fn convert_sidechain_id(id: SideChainId) -> tari_rpc::SideChainId {
    tari_rpc::SideChainId {
        public_key: id.public_key().to_vec(),
        knowledge_proof: Some(convert_signature(id.knowledge_proof().clone())),
    }
}

fn convert_sidechain_feature(feature: SideChainFeature) -> tari_rpc::SideChainFeature {
    tari_rpc::SideChainFeature {
        feature: Some(convert_sidechain_feature_data(feature.data)),
        sidechain_id: feature.sidechain_id.map(convert_sidechain_id),
    }
}

fn convert_output_features(features: OutputFeatures) -> tari_rpc::OutputFeatures {
    tari_rpc::OutputFeatures {
        version: features.version as u32,
        output_type: u32::from(features.output_type.as_byte()),
        maturity: features.maturity,
        coinbase_extra: features.coinbase_extra.to_vec(),
        sidechain_feature: features.sidechain_feature.map(convert_sidechain_feature),
        range_proof_type: u32::from(features.range_proof_type.as_byte()),
    }
}

fn convert_transaction_input(input: TransactionInput) -> tari_rpc::TransactionInput {
    let script_signature = Some(tari_rpc::ComAndPubSignature {
        ephemeral_commitment: Vec::from(input.script_signature.ephemeral_commitment().as_bytes()),
        ephemeral_pubkey: Vec::from(input.script_signature.ephemeral_pubkey().as_bytes()),
        u_a: Vec::from(input.script_signature.u_a().as_bytes()),
        u_x: Vec::from(input.script_signature.u_x().as_bytes()),
        u_y: Vec::from(input.script_signature.u_y().as_bytes()),
    });
    if input.is_compact() {
        let output_hash = input.output_hash().to_vec();
        tari_rpc::TransactionInput {
            script_signature,
            output_hash,
            ..Default::default()
        }
    } else {
        let features = input
            .features()
            .expect("Non-compact Transaction input should contain features");
        let metadata_signature = input
            .metadata_signature()
            .expect("Non-compact Transaction input should contain a metadata_signature")
            .clone();
        tari_rpc::TransactionInput {
            features: Some(convert_output_features(features.clone())),
            commitment: input
                .commitment()
                .expect("Non-compact Transaction input should contain commitment")
                .to_vec(),
            hash: input.canonical_hash().to_vec(),

            script: input
                .script()
                .expect("Non-compact Transaction input should contain script")
                .to_bytes(),
            input_data: input.input_data.to_bytes(),
            script_signature,
            sender_offset_public_key: input
                .sender_offset_public_key()
                .expect("Non-compact Transaction input should contain sender_offset_public_key")
                .to_vec(),
            output_hash: Vec::new(),
            covenant: borsh::to_vec(
                &input
                    .covenant()
                    .expect("Non-compact Transaction input should contain covenant"),
            )
            .unwrap(),
            version: input.version as u32,
            encrypted_data: input
                .encrypted_data()
                .expect("Non-compact Transaction input should contain encrypted value")
                .to_byte_vec(),
            metadata_signature: Some(tari_rpc::ComAndPubSignature {
                ephemeral_commitment: Vec::from(
                    metadata_signature.ephemeral_commitment().as_bytes(),
                ),
                ephemeral_pubkey: Vec::from(metadata_signature.ephemeral_pubkey().as_bytes()),
                u_a: Vec::from(metadata_signature.u_a().as_bytes()),
                u_x: Vec::from(metadata_signature.u_x().as_bytes()),
                u_y: Vec::from(metadata_signature.u_y().as_bytes()),
            }),
            rangeproof_hash: input
                .rangeproof_hash()
                .expect("Non-compact Transaction input should contain a rangeproof hash")
                .to_vec(),
            minimum_value_promise: input
                .minimum_value_promise()
                .expect("Non-compact Transaction input should contain the minimum value promise")
                .as_u64(),
        }
    }
}

fn convert_transaction_output(
    output: TransactionOutput,
    block_hash: Option<BlockHash>,
) -> tari_rpc::TransactionOutput {
    let output_hash = output.hash();
    let mut covenant = Vec::new();
    BorshSerialize::serialize(&output.covenant, &mut covenant).unwrap();
    let range_proof = output.proof.map(|proof| tari_rpc::RangeProof {
        proof_bytes: proof.to_vec(),
    });
    tari_rpc::TransactionOutput {
        hash: output_hash.to_vec(),
        features: Some(convert_output_features(output.features)),
        commitment: Vec::from(output.commitment.as_bytes()),
        range_proof,
        script: output.script.to_bytes(),
        sender_offset_public_key: output.sender_offset_public_key.as_bytes().to_vec(),
        metadata_signature: Some(tari_rpc::ComAndPubSignature {
            ephemeral_commitment: Vec::from(
                output.metadata_signature.ephemeral_commitment().as_bytes(),
            ),
            ephemeral_pubkey: Vec::from(output.metadata_signature.ephemeral_pubkey().as_bytes()),
            u_a: Vec::from(output.metadata_signature.u_a().as_bytes()),
            u_x: Vec::from(output.metadata_signature.u_x().as_bytes()),
            u_y: Vec::from(output.metadata_signature.u_y().as_bytes()),
        }),
        covenant,
        version: output.version as u32,
        encrypted_data: output.encrypted_data.to_byte_vec(),
        minimum_value_promise: output.minimum_value_promise.into(),
        // Payment reference will be populated when the output is included in a block
        // and the block hash is available
        payment_reference: if let Some(hash) = block_hash {
            generate_payment_reference(&hash, &output_hash).to_vec()
        } else {
            vec![]
        },
    }
}

fn convert_transaction_kernel(kernel: TransactionKernel) -> tari_rpc::TransactionKernel {
    let hash = kernel.hash().to_vec();
    let commitment = match kernel.burn_commitment {
        Some(c) => c.as_bytes().to_vec(),
        None => vec![],
    };

    tari_rpc::TransactionKernel {
        features: u32::from(kernel.features.bits()),
        fee: kernel.fee.0,
        lock_height: kernel.lock_height,
        excess: Vec::from(kernel.excess.as_bytes()),
        excess_sig: Some(tari_rpc::Signature {
            public_nonce: Vec::from(kernel.excess_sig.get_compressed_public_nonce().as_bytes()),
            signature: Vec::from(kernel.excess_sig.get_signature().as_bytes()),
        }),
        hash,
        version: kernel.version as u32,
        burn_commitment: commitment,
    }
}

fn convert_aggregate_body(
    body: AggregateBody,
    block_hash: Option<BlockHash>,
) -> tari_rpc::AggregateBody {
    tari_rpc::AggregateBody {
        inputs: body
            .inputs()
            .iter()
            .cloned()
            .map(convert_transaction_input)
            .collect(),
        outputs: body
            .outputs()
            .iter()
            .cloned()
            .map(|o| convert_transaction_output(o, block_hash))
            .collect(),
        kernels: body
            .kernels()
            .iter()
            .cloned()
            .map(convert_transaction_kernel)
            .collect(),
    }
}

pub fn convert_transaction(transaction: Transaction) -> tari_rpc::Transaction {
    tari_rpc::Transaction {
        offset: Vec::from(transaction.offset.as_bytes()),
        body: Some(convert_aggregate_body(transaction.body, None)),
        script_offset: Vec::from(transaction.script_offset.as_bytes()),
    }
}
