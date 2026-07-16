use doge_light_client::{
    common_types::QHash256, doge::transaction::BTCTransaction,
    hash::merkle::in_memory::compute_dogecoin_block_transaction_merkle_proof_tree_root_hash256,
};

use crate::claim::block_tx_output_tree::TXO_TREE_INDEX_BITS_TOP_OUTPUT_NUM_LENGTH;
use crate::{
    claim::transition::transition_builder::BlockTransitionBuilder,
    utils::bit_vector_append_only_tree_builder::BitVectorAppendOnlyMerkleTreeFixed,
};

#[cfg_attr(
    feature = "serialize_serde",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(
    feature = "serialize_borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(
    feature = "serialize_speedy",
    derive(speedy::Readable, speedy::Writable)
)]
#[cfg_attr(
    feature = "serialize_bytemuck",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
#[repr(C)]
pub struct PsyBridgeClaimDepositItem {
    pub output_index: u32,
    pub public_key_index: u32,
}

#[cfg_attr(
    feature = "serialize_serde",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(
    feature = "serialize_borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(
    feature = "serialize_speedy",
    derive(speedy::Readable, speedy::Writable)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct PsyBridgeClaimBlockTransactionWitness {
    pub transaction_index: u32,
    pub btc_transaction_tree_siblings: Vec<QHash256>,
    pub deposit_outputs: Vec<PsyBridgeClaimDepositItem>,
    pub transaction: BTCTransaction,
}

impl PsyBridgeClaimBlockTransactionWitness {
    pub fn new(
        transaction_index: u32,
        btc_transaction_tree_siblings: Vec<QHash256>,
        deposit_outputs: Vec<PsyBridgeClaimDepositItem>,
        transaction: BTCTransaction,
    ) -> Self {
        Self {
            transaction_index,
            btc_transaction_tree_siblings,
            deposit_outputs,
            transaction,
        }
    }

    pub fn verify_and_add_to_transition_builder(
        &self,
        transition_builder: &mut BlockTransitionBuilder,
        block_transaction_tree_root: &QHash256,
    ) -> anyhow::Result<()> {
        let transaction_hash = self.transaction.get_hash();
        let computed_root = compute_dogecoin_block_transaction_merkle_proof_tree_root_hash256(
            transaction_hash,
            &self.btc_transaction_tree_siblings,
            self.transaction_index,
        );
        if computed_root.is_none() || computed_root.as_ref().unwrap() != block_transaction_tree_root
        {
            anyhow::bail!("Transaction Merkle Proof verification failed, merkle proof for block transaction tree root does not match");
        }
        let mut txo_builder = BitVectorAppendOnlyMerkleTreeFixed::<
            TXO_TREE_INDEX_BITS_TOP_OUTPUT_NUM_LENGTH,
        >::new_from_empty();

        let mut last_deposit_output_index = None;
        for claim_output in &self.deposit_outputs {
            if let Some(last_index) = last_deposit_output_index {
                if claim_output.output_index <= last_index {
                    anyhow::bail!(
                        "Deposit outputs must be in strictly increasing order by output_index"
                    );
                }
            }
            last_deposit_output_index = Some(claim_output.output_index);

            if self.transaction.outputs.len() <= claim_output.output_index as usize {
                anyhow::bail!("Deposit output index out of bounds for transaction outputs");
            }

            let output = &self.transaction.outputs[claim_output.output_index as usize];
            let pub_key_index = claim_output.public_key_index as usize;
            let expected_output_script =
                transition_builder.get_expected_output_script_by_public_key_index(pub_key_index)?;
            if &output.script != expected_output_script {
                anyhow::bail!(
                    "Deposit output script does not match expected script for user public key"
                );
            }

            transition_builder.add_deposit(
                &transaction_hash,
                claim_output.output_index,
                pub_key_index,
                output.value,
            )?;
            txo_builder.set_true_bit_at(claim_output.output_index);
        }
        transition_builder
            .set_txo_transaction_leaf(self.transaction_index, &txo_builder.finalize_into_root());

        Ok(())
    }
}

#[cfg(test)]
mod manager_custody_validation_tests {
    use super::*;
    use crate::{
        claim::{
            auto_claim_deposits_tree::constants::AUTO_CLAIM_DEPOSITS_TREE_HEIGHT,
            transition::transition_builder::BlockTransitionBuilder,
        },
        tx_template::{
            get_manager_custody_output_script, CustodyScriptConfig,
            MANAGER_CUSTODY_PUBLIC_KEYS, MANAGER_CUSTODY_THRESHOLD,
        },
        utils::sha256_zero_hashes::SHA256_ZERO_HASHES,
    };
    use doge_light_client::doge::transaction::BTCTransactionOutput;

    const BRIDGE_STATE_PDA: [u8; 32] = [
        0x84, 0xb2, 0x67, 0xdd, 0x47, 0x47, 0x4d, 0xd7, 0xee, 0x3b, 0x7d, 0x7f, 0xb5, 0xb1,
        0x0d, 0x86, 0x26, 0xbf, 0x52, 0xff, 0x8d, 0x2c, 0x82, 0x13, 0x57, 0x70, 0xfe, 0xad,
        0x3a, 0x5a, 0xb1, 0xba,
    ];
    const RECIPIENT_ATA: [u8; 32] = [
        0x54, 0x84, 0x4c, 0xc4, 0x57, 0x75, 0x70, 0x12, 0x29, 0xdb, 0x39, 0x99, 0x24, 0xa6,
        0xce, 0x19, 0x20, 0xc3, 0x2e, 0xc2, 0xf0, 0x08, 0x2c, 0xfc, 0x64, 0x92, 0x3d, 0x44,
        0x62, 0x4b, 0xe0, 0x14,
    ];

    fn transition_builder(
        config: &CustodyScriptConfig,
        recipient_ata: [u8; 32],
    ) -> BlockTransitionBuilder {
        BlockTransitionBuilder::new_from_siblings(
            1,
            0,
            0,
            1,
            &[[0u8; 32]; AUTO_CLAIM_DEPOSITS_TREE_HEIGHT],
            0,
            &SHA256_ZERO_HASHES[0],
            config,
            vec![recipient_ata],
        )
        .unwrap()
    }

    fn deposit_witness(script: [u8; 23]) -> PsyBridgeClaimBlockTransactionWitness {
        let transaction = BTCTransaction::from_io(
            vec![],
            vec![BTCTransactionOutput {
                value: 100_000_000,
                script: script.to_vec(),
            }],
        );
        PsyBridgeClaimBlockTransactionWitness::new(
            0,
            vec![],
            vec![PsyBridgeClaimDepositItem {
                output_index: 0,
                public_key_index: 0,
            }],
            transaction,
        )
    }

    #[test]
    fn validator_accepts_exact_manager_output_and_mints_to_ata() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let script = get_manager_custody_output_script(&config, &RECIPIENT_ATA);
        let witness = deposit_witness(script);
        let transaction_root = witness.transaction.get_hash();
        let mut builder = transition_builder(&config, RECIPIENT_ATA);

        witness
            .verify_and_add_to_transition_builder(&mut builder, &transaction_root)
            .unwrap();

        assert_eq!(builder.depositor_public_keys, vec![RECIPIENT_ATA]);
        assert_eq!(builder.total_mints, 1);
        assert_eq!(&builder.pending_mints.current_group[..32], &RECIPIENT_ATA);
    }

    #[test]
    fn validator_rejects_mutated_emitter_or_recipient() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let expected = get_manager_custody_output_script(&config, &RECIPIENT_ATA);

        let mut emitter = BRIDGE_STATE_PDA;
        emitter[0] ^= 1;
        let mut builder = transition_builder(&CustodyScriptConfig::new(emitter), RECIPIENT_ATA);
        let witness = deposit_witness(expected);
        let transaction_root = witness.transaction.get_hash();
        assert!(witness
            .verify_and_add_to_transition_builder(&mut builder, &transaction_root)
            .is_err());

        let mut recipient = RECIPIENT_ATA;
        recipient[31] ^= 1;
        let mut builder = transition_builder(&config, recipient);
        let witness = deposit_witness(expected);
        let transaction_root = witness.transaction.get_hash();
        assert!(witness
            .verify_and_add_to_transition_builder(&mut builder, &transaction_root)
            .is_err());
    }

    #[test]
    fn config_rejects_mutated_key_or_threshold_before_validation() {
        let mut keys = MANAGER_CUSTODY_PUBLIC_KEYS;
        keys[0][1] ^= 1;
        assert!(CustodyScriptConfig::try_from_manager_set(
            BRIDGE_STATE_PDA,
            MANAGER_CUSTODY_THRESHOLD,
            &keys,
        )
        .is_err());
        assert!(CustodyScriptConfig::try_from_manager_set(
            BRIDGE_STATE_PDA,
            MANAGER_CUSTODY_THRESHOLD + 1,
            &MANAGER_CUSTODY_PUBLIC_KEYS,
        )
        .is_err());
    }
}
