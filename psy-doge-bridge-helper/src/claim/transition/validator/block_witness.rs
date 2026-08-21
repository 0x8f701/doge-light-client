use doge_light_client::{
    common_types::QHash256,
    hash::{
        merkle::in_memory::compute_dogecoin_block_transaction_merkle_proof_tree_root_hash256,
        sha256_impl::hash_impl_sha256_bytes,
    },
};

use crate::claim::{
    auto_claim_deposits_tree::{
        constants::AUTO_CLAIM_DEPOSITS_TREE_HEIGHT,
        pending_mints_buffer_builder::PendingMintsGroupsBuilder,
    },
    block_tx_output_tree::{TXO_TREE_INDEX_BITS_BLOCK_NUM_LENGTH, TXO_TREE_MAX_OUTPUTS_PER_TX},
    transition::{
        transition_builder::{calcuate_fee, BlockTransitionBuilder},
        validator::tx_witness::PsyBridgeClaimBlockTransactionWitness,
    },
};
use crate::tx_template::{
    get_manager_custody_output_script, CustodyScriptConfig, ManagerCustodyProfile,
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
pub struct PsyBridgeClaimBlockWitnessHeader {
    pub txo_tree_block_siblings: [QHash256; TXO_TREE_INDEX_BITS_BLOCK_NUM_LENGTH],
    pub last_auto_claimed_deposits_siblings: [QHash256; AUTO_CLAIM_DEPOSITS_TREE_HEIGHT],
    pub total_outputs_hint: u32,
    pub claim_deposits_last_index: u32,
    pub claim_deposits_last_value: QHash256,
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
#[cfg_attr(
    feature = "serialize_bytemuck",
    derive(bytemuck::Pod, bytemuck::Zeroable)
)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
#[repr(C)]
pub struct PsyBridgeClaimBlockWitnessVerifyResult {
    pub old_claimed_txo_tree_root: QHash256,
    pub new_claimed_txo_tree_root: QHash256,
    pub old_auto_claimed_deposits_tree_root: QHash256,
    pub new_auto_claimed_deposits_tree_root: QHash256,
    pub start_auto_claimed_deposits_index: u32,
    pub end_auto_claimed_deposits_index: u32,
    pub fees_collected: u64,
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
pub struct PsyBridgeClaimBlockWitness {
    pub header: PsyBridgeClaimBlockWitnessHeader,
    pub deposit_solana_public_keys: Vec<[u8; 32]>,
    pub deposit_transactions: Vec<PsyBridgeClaimBlockTransactionWitness>,
}

impl PsyBridgeClaimBlockWitness {
    pub fn new(
        header: PsyBridgeClaimBlockWitnessHeader,
        deposit_solana_public_keys: Vec<[u8; 32]>,
        deposit_transactions: Vec<PsyBridgeClaimBlockTransactionWitness>,
    ) -> Self {
        Self {
            header,
            deposit_solana_public_keys,
            deposit_transactions,
        }
    }

    pub fn verify_and_get_result<P: ManagerCustodyProfile>(
        &self,
        block_height: u32,
        block_transaction_tree_merkle_root: QHash256,
        custody_script_config: CustodyScriptConfig,
        flat_fee_per_deposit_sats: u64,
        deposit_fee_rate_numerator: u64,
        deposit_fee_rate_denominator: u64,
    ) -> anyhow::Result<PsyBridgeClaimBlockWitnessVerifyResult> {
        let mut transition_builder = BlockTransitionBuilder::new_from_siblings::<P>(
            self.header.total_outputs_hint as usize,
            flat_fee_per_deposit_sats,
            deposit_fee_rate_numerator,
            deposit_fee_rate_denominator,
            &self.header.last_auto_claimed_deposits_siblings,
            self.header.claim_deposits_last_index,
            &self.header.claim_deposits_last_value,
            &custody_script_config,
            self.deposit_solana_public_keys.clone(),
        )?;
        for deposit in &self.deposit_transactions {
            deposit.verify_and_add_to_transition_builder(
                &mut transition_builder,
                &block_transaction_tree_merkle_root,
            )?;
        }

        transition_builder.finalize(
            block_height,
            self.header.claim_deposits_last_index,
            &self.header.claim_deposits_last_value,
            flat_fee_per_deposit_sats,
            deposit_fee_rate_numerator,
            deposit_fee_rate_denominator,
            &self.header.txo_tree_block_siblings,
        )
    }
}

/// Combined TXO list index used by Solana `txo_output_list_finalized_hash`.
pub fn combined_txo_index(transaction_index: u32, output_index: u32) -> anyhow::Result<u32> {
    let max_outputs = TXO_TREE_MAX_OUTPUTS_PER_TX as u32;
    transaction_index
        .checked_mul(max_outputs)
        .and_then(|index| index.checked_add(output_index))
        .ok_or_else(|| anyhow::anyhow!("combined TXO index overflow"))
}

/// Recompute Solana pending-mint and TXO-list hashes from a claim witness.
///
/// Each listed deposit must merkle-prove into `block_transaction_tree_merkle_root`
/// and pay the claimed recipient's manager-custody script. Hashes then bind
/// `recipient || net_amount` and `tx_index * MAX_OUTPUTS_PER_TX + vout`.
pub fn pending_mint_and_txo_hashes_from_claim_witness<P: ManagerCustodyProfile>(
    witness: &PsyBridgeClaimBlockWitness,
    block_transaction_tree_merkle_root: QHash256,
    custody_script_config: &CustodyScriptConfig,
    flat_fee_per_deposit_sats: u64,
    deposit_fee_rate_numerator: u64,
    deposit_fee_rate_denominator: u64,
) -> anyhow::Result<(QHash256, QHash256)> {
    let expected_scripts: Vec<[u8; 23]> = witness
        .deposit_solana_public_keys
        .iter()
        .map(|recipient_ata| {
            get_manager_custody_output_script::<P>(custody_script_config, recipient_ata)
        })
        .collect();

    let mut pending_mints =
        PendingMintsGroupsBuilder::new_with_hint(witness.header.total_outputs_hint as usize);
    let mut txo_index_bytes = Vec::with_capacity(witness.header.total_outputs_hint as usize * 4);
    let mut deposit_count = 0u32;

    for transaction_witness in &witness.deposit_transactions {
        let transaction_hash = transaction_witness.transaction.get_hash();
        let computed_root = compute_dogecoin_block_transaction_merkle_proof_tree_root_hash256(
            transaction_hash,
            &transaction_witness.btc_transaction_tree_siblings,
            transaction_witness.transaction_index,
        );
        if computed_root.as_ref() != Some(&block_transaction_tree_merkle_root) {
            anyhow::bail!(
                "Transaction Merkle Proof verification failed, merkle proof for block transaction tree root does not match"
            );
        }

        let mut last_deposit_output_index = None;
        for deposit in &transaction_witness.deposit_outputs {
            if let Some(last_index) = last_deposit_output_index {
                if deposit.output_index <= last_index {
                    anyhow::bail!(
                        "Deposit outputs must be in strictly increasing order by output_index"
                    );
                }
            }
            last_deposit_output_index = Some(deposit.output_index);

            let public_key = witness
                .deposit_solana_public_keys
                .get(deposit.public_key_index as usize)
                .ok_or_else(|| anyhow::anyhow!("deposit public key index out of bounds"))?;
            let expected_script = expected_scripts
                .get(deposit.public_key_index as usize)
                .ok_or_else(|| anyhow::anyhow!("deposit public key index out of bounds"))?;
            let output = transaction_witness
                .transaction
                .outputs
                .get(deposit.output_index as usize)
                .ok_or_else(|| anyhow::anyhow!("deposit output index out of bounds"))?;
            if output.script.as_slice() != expected_script.as_slice() {
                anyhow::bail!(
                    "Deposit output script does not match expected script for user public key"
                );
            }
            let (_, net_amount) = calcuate_fee(
                output.value,
                flat_fee_per_deposit_sats,
                deposit_fee_rate_numerator,
                deposit_fee_rate_denominator,
            )?;
            pending_mints.append_pending_mint(public_key, net_amount);
            let combined =
                combined_txo_index(transaction_witness.transaction_index, deposit.output_index)?;
            txo_index_bytes.extend_from_slice(&combined.to_le_bytes());
            deposit_count = deposit_count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("deposit count overflow"))?;
        }
    }

    if deposit_count != witness.header.total_outputs_hint {
        anyhow::bail!(
            "witness total_outputs_hint {} does not match {} deposit outputs",
            witness.header.total_outputs_hint,
            deposit_count
        );
    }

    Ok((
        pending_mints.finalize()?,
        hash_impl_sha256_bytes(&txo_index_bytes),
    ))
}

#[cfg(test)]
mod pending_mint_and_txo_hash_tests {
    use super::*;
    use crate::{
        claim::transition::validator::tx_witness::PsyBridgeClaimDepositItem,
        tx_template::{
            get_manager_custody_output_script, CustodyScriptConfig, LocalRegtestManagerCustody,
        },
        utils::sha256_zero_hashes::SHA256_ZERO_HASHES,
    };
    use doge_light_client::doge::transaction::{BTCTransaction, BTCTransactionOutput};

    const BRIDGE_STATE_PDA: [u8; 32] = [
        0xf0, 0x27, 0x32, 0x70, 0x89, 0x65, 0xbb, 0x94, 0x73, 0x17, 0x74, 0x95, 0xe6, 0x08, 0x49,
        0x6b, 0x0a, 0xf3, 0xbd, 0xbe, 0x5b, 0xd6, 0x2e, 0xc0, 0x62, 0xd8, 0xcd, 0xdb, 0x18, 0x24,
        0xa8, 0x13,
    ];
    const RECIPIENT_ATA: [u8; 32] = [
        0x54, 0x84, 0x4c, 0xc4, 0x57, 0x75, 0x70, 0x12, 0x29, 0xdb, 0x39, 0x99, 0x24, 0xa6, 0xce,
        0x19, 0x20, 0xc3, 0x2e, 0xc2, 0xf0, 0x08, 0x2c, 0xfc, 0x64, 0x92, 0x3d, 0x44, 0x62, 0x4b,
        0xe0, 0x14,
    ];

    fn empty_header(total_outputs_hint: u32) -> PsyBridgeClaimBlockWitnessHeader {
        PsyBridgeClaimBlockWitnessHeader {
            txo_tree_block_siblings: [[0u8; 32]; TXO_TREE_INDEX_BITS_BLOCK_NUM_LENGTH],
            last_auto_claimed_deposits_siblings: [[0u8; 32]; AUTO_CLAIM_DEPOSITS_TREE_HEIGHT],
            total_outputs_hint,
            claim_deposits_last_index: 0,
            claim_deposits_last_value: SHA256_ZERO_HASHES[0],
        }
    }

    fn deposit_transaction_witness(
        transaction_index: u32,
        value: u64,
        recipient_ata: [u8; 32],
    ) -> PsyBridgeClaimBlockTransactionWitness {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let script = get_manager_custody_output_script::<LocalRegtestManagerCustody>(
            &config,
            &recipient_ata,
        );
        let transaction = BTCTransaction::from_io(
            vec![],
            vec![BTCTransactionOutput {
                value,
                script: script.to_vec(),
            }],
        );
        PsyBridgeClaimBlockTransactionWitness::new(
            transaction_index,
            vec![],
            vec![PsyBridgeClaimDepositItem {
                output_index: 0,
                public_key_index: 0,
            }],
            transaction,
        )
    }

    #[test]
    fn empty_witness_matches_empty_buffer_hashes() {
        let witness = PsyBridgeClaimBlockWitness::new(empty_header(0), vec![], vec![]);
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let (mint_hash, txo_hash) = pending_mint_and_txo_hashes_from_claim_witness::<
            LocalRegtestManagerCustody,
        >(&witness, [0u8; 32], &config, 0, 0, 1)
        .unwrap();
        assert_eq!(
            mint_hash,
            PendingMintsGroupsBuilder::new_with_hint(0)
                .finalize()
                .unwrap()
        );
        assert_eq!(txo_hash, hash_impl_sha256_bytes(&[]));
    }

    #[test]
    fn one_deposit_binds_recipient_amount_and_txo_index() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let tx_witness = deposit_transaction_witness(0, 100_000_000, RECIPIENT_ATA);
        let merkle_root = tx_witness.transaction.get_hash();
        let witness = PsyBridgeClaimBlockWitness::new(
            empty_header(1),
            vec![RECIPIENT_ATA],
            vec![tx_witness],
        );
        let (mint_hash, txo_hash) = pending_mint_and_txo_hashes_from_claim_witness::<
            LocalRegtestManagerCustody,
        >(&witness, merkle_root, &config, 0, 0, 1)
        .unwrap();

        let mut expected_mints = PendingMintsGroupsBuilder::new_with_hint(1);
        expected_mints.append_pending_mint(&RECIPIENT_ATA, 100_000_000);
        assert_eq!(mint_hash, expected_mints.finalize().unwrap());
        assert_eq!(txo_hash, hash_impl_sha256_bytes(&0u32.to_le_bytes()));
    }

    #[test]
    fn mutated_recipient_or_merkle_root_is_rejected() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let tx_witness = deposit_transaction_witness(0, 100_000_000, RECIPIENT_ATA);
        let merkle_root = tx_witness.transaction.get_hash();
        let mut poisoned_recipient = RECIPIENT_ATA;
        poisoned_recipient[0] ^= 1;
        let witness = PsyBridgeClaimBlockWitness::new(
            empty_header(1),
            vec![poisoned_recipient],
            vec![tx_witness.clone()],
        );
        assert!(pending_mint_and_txo_hashes_from_claim_witness::<
            LocalRegtestManagerCustody,
        >(&witness, merkle_root, &config, 0, 0, 1)
        .is_err());

        let honest = PsyBridgeClaimBlockWitness::new(
            empty_header(1),
            vec![RECIPIENT_ATA],
            vec![tx_witness],
        );
        let mut bad_root = merkle_root;
        bad_root[0] ^= 1;
        assert!(pending_mint_and_txo_hashes_from_claim_witness::<
            LocalRegtestManagerCustody,
        >(&honest, bad_root, &config, 0, 0, 1)
        .is_err());
    }

    #[test]
    fn different_net_amount_changes_pending_mints_hash() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let first = deposit_transaction_witness(0, 100_000_000, RECIPIENT_ATA);
        let second = deposit_transaction_witness(0, 90_000_000, RECIPIENT_ATA);
        let first_hash = pending_mint_and_txo_hashes_from_claim_witness::<
            LocalRegtestManagerCustody,
        >(
            &PsyBridgeClaimBlockWitness::new(
                empty_header(1),
                vec![RECIPIENT_ATA],
                vec![first.clone()],
            ),
            first.transaction.get_hash(),
            &config,
            0,
            0,
            1,
        )
        .unwrap()
        .0;
        let second_hash = pending_mint_and_txo_hashes_from_claim_witness::<
            LocalRegtestManagerCustody,
        >(
            &PsyBridgeClaimBlockWitness::new(empty_header(1), vec![RECIPIENT_ATA], vec![second.clone()]),
            second.transaction.get_hash(),
            &config,
            0,
            0,
            1,
        )
        .unwrap()
        .0;
        assert_ne!(first_hash, second_hash);
    }
}
