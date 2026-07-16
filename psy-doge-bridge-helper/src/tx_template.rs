/*
Copyright (C) 2025 Zero Knowledge Labs Limited, Psy Protocol

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Additional terms under GNU AGPL version 3 section 7:

As permitted by section 7(b) of the GNU Affero General Public License,
you must retain the following attribution notice in all copies or
substantial portions of the software:

"This software was created by Psy Protocol (https://psy.xyz)
with contributions from Carter Feldman (https://x.com/cmpeq)."
*/

use doge_light_client::{
    common_types::QHash256,
    doge::{
        address::{gen_p2sh_script, BTCAddress160, BTCAddressType},
        transaction::BTCTransactionOutput,
    },
    hash::{
        ripemd160::QBTCHash160Hasher,
        sha256_impl::hash_impl_sha256_bytes,
        traits::BytesHasher,
    },
};

const OP_PUSHBYTES_2: u8 = 0x02;
const OP_PUSHBYTES_32: u8 = 0x20;
const OP_PUSHBYTES_33: u8 = 0x21;
const OP_2DROP: u8 = 0x6b;
const OP_DROP: u8 = 117;
const OP_DUP: u8 = 118;
const OP_EQUALVERIFY: u8 = 136;
const OP_HASH160: u8 = 169;
const OP_CHECKSIG: u8 = 172;
const OP_CHECKMULTISIG: u8 = 174;
const OP_PUSHBYTES_20: u8 = 0x14;

pub const SOLANA_WORMHOLE_CHAIN_ID: u16 = 1;
pub const MANAGER_CUSTODY_THRESHOLD: u8 = 5;
pub const MANAGER_CUSTODY_KEY_COUNT: usize = 7;
pub const MANAGER_CUSTODY_REDEEM_SCRIPT_SIZE: usize = 312;
pub const MANAGER_CUSTODY_CONFIG_ID: u32 = 0;
pub const MANAGER_CUSTODY_NETWORK_TYPE: u16 = 0;
pub const MANAGER_CUSTODY_WALLET_CONFIG_SIZE: usize = 264;

pub const MANAGER_CUSTODY_PUBLIC_KEYS: [[u8; 33]; MANAGER_CUSTODY_KEY_COUNT] = [
    [0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98],
    [0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5],
    [0x02, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9],
    [0x02, 0xe4, 0x93, 0xdb, 0xf1, 0xc1, 0x0d, 0x80, 0xf3, 0x58, 0x1e, 0x49, 0x04, 0x93, 0x0b, 0x14, 0x04, 0xcc, 0x6c, 0x13, 0x90, 0x0e, 0xe0, 0x75, 0x84, 0x74, 0xfa, 0x94, 0xab, 0xe8, 0xc4, 0xcd, 0x13],
    [0x02, 0x2f, 0x8b, 0xde, 0x4d, 0x1a, 0x07, 0x20, 0x93, 0x55, 0xb4, 0xa7, 0x25, 0x0a, 0x5c, 0x51, 0x28, 0xe8, 0x8b, 0x84, 0xbd, 0xdc, 0x61, 0x9a, 0xb7, 0xcb, 0xa8, 0xd5, 0x69, 0xb2, 0x40, 0xef, 0xe4],
    [0x03, 0xff, 0xf9, 0x7b, 0xd5, 0x75, 0x5e, 0xee, 0xa4, 0x20, 0x45, 0x3a, 0x14, 0x35, 0x52, 0x35, 0xd3, 0x82, 0xf6, 0x47, 0x2f, 0x85, 0x68, 0xa1, 0x8b, 0x2f, 0x05, 0x7a, 0x14, 0x60, 0x29, 0x75, 0x56],
    [0x02, 0x5c, 0xbd, 0xf0, 0x64, 0x6e, 0x5d, 0xb4, 0xea, 0xa3, 0x98, 0xf3, 0x65, 0xf2, 0xea, 0x7a, 0x0e, 0x3d, 0x41, 0x9b, 0x7e, 0x03, 0x30, 0xe3, 0x9c, 0xe9, 0x2b, 0xdd, 0xed, 0xca, 0xc4, 0xf9, 0xbc],
];

#[cfg_attr(feature = "serialize_serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serialize_borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
#[cfg_attr(feature = "serialize_bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct CustodyScriptConfig {
    pub emitter_bridge_pda: [u8; 32],
}

impl CustodyScriptConfig {
    pub const fn new(emitter_bridge_pda: [u8; 32]) -> Self {
        Self { emitter_bridge_pda }
    }

    pub const fn to_preimage_bytes(self) -> [u8; 32] {
        self.emitter_bridge_pda
    }

    pub fn hash(&self) -> QHash256 {
        let mut wallet_config = [0u8; MANAGER_CUSTODY_WALLET_CONFIG_SIZE];
        wallet_config[..32].copy_from_slice(&self.emitter_bridge_pda);

        let mut y_parity = 0u16;
        for (index, compressed_public_key) in MANAGER_CUSTODY_PUBLIC_KEYS.iter().enumerate() {
            let key_offset = 32 + index * 32;
            wallet_config[key_offset..key_offset + 32]
                .copy_from_slice(&compressed_public_key[1..]);
            if compressed_public_key[0] == 0x03 {
                y_parity |= 1 << index;
            }
        }
        wallet_config[256..260].copy_from_slice(&MANAGER_CUSTODY_CONFIG_ID.to_le_bytes());
        wallet_config[260..262].copy_from_slice(&y_parity.to_le_bytes());
        wallet_config[262..264].copy_from_slice(&MANAGER_CUSTODY_NETWORK_TYPE.to_le_bytes());

        hash_impl_sha256_bytes(&wallet_config)
    }

    pub fn try_from_manager_set(
        emitter_bridge_pda: [u8; 32],
        threshold: u8,
        public_keys: &[[u8; 33]],
    ) -> anyhow::Result<Self> {
        if threshold != MANAGER_CUSTODY_THRESHOLD {
            anyhow::bail!(
                "Custody manager threshold mismatch: expected {}, got {}",
                MANAGER_CUSTODY_THRESHOLD,
                threshold
            );
        }
        if public_keys != MANAGER_CUSTODY_PUBLIC_KEYS {
            anyhow::bail!("Custody manager public keys do not match the canonical manager set");
        }
        Ok(Self::new(emitter_bridge_pda))
    }
}

//  size = 1 + 32 + 4 + 20 + 2 = 59
pub const STANDARD_TRANSFER_WITH_MESSAGE_TEMPLATE: [u8; 59] = psy_doge_macros::const_concat_arrays!(
    [OP_PUSHBYTES_32],
    [0; 32], // 1..33
    [OP_DROP, OP_DUP, OP_HASH160, OP_PUSHBYTES_20],
    [0; 20], // 37..57
    [OP_EQUALVERIFY, OP_CHECKSIG]
);

pub fn get_transfer_with_message_redeem_script(message: &[u8], public_key_hash: &[u8]) -> [u8; 59] {
    let mut base = STANDARD_TRANSFER_WITH_MESSAGE_TEMPLATE.clone();
    base[1..33].copy_from_slice(message);
    base[37..57].copy_from_slice(public_key_hash);

    base
}

pub fn get_bridge_deposit_address_hash_v1(
    user_public_key: &[u8],
    bridge_public_key_hash: &[u8],
) -> [u8; 20] {
    QBTCHash160Hasher::hash_bytes(&get_transfer_with_message_redeem_script(
        user_public_key,
        bridge_public_key_hash,
    ))
}

pub fn get_bridge_deposit_address_v1(
    user_public_key: &[u8],
    bridge_public_key_hash: &[u8],
) -> BTCAddress160 {
    BTCAddress160 {
        address_type: BTCAddressType::P2SH,
        address: get_bridge_deposit_address_hash_v1(user_public_key, bridge_public_key_hash),
    }
}
pub fn get_bridge_deposit_output_script(
    user_public_key: &[u8],
    bridge_public_key_hash: &[u8],
) -> [u8; 23] {
    gen_p2sh_script(&get_bridge_deposit_address_hash_v1(
        user_public_key,
        bridge_public_key_hash,
    ))
}

pub fn get_manager_custody_redeem_script(
    custody_script_config: &CustodyScriptConfig,
    recipient_ata: &[u8; 32],
) -> [u8; MANAGER_CUSTODY_REDEEM_SCRIPT_SIZE] {
    let mut script = [0u8; MANAGER_CUSTODY_REDEEM_SCRIPT_SIZE];
    let mut offset = 0usize;

    script[offset] = OP_PUSHBYTES_2;
    offset += 1;
    script[offset..offset + 2].copy_from_slice(&SOLANA_WORMHOLE_CHAIN_ID.to_be_bytes());
    offset += 2;
    script[offset] = OP_PUSHBYTES_32;
    offset += 1;
    script[offset..offset + 32].copy_from_slice(&custody_script_config.emitter_bridge_pda);
    offset += 32;
    script[offset] = OP_2DROP;
    offset += 1;
    script[offset] = OP_PUSHBYTES_32;
    offset += 1;
    script[offset..offset + 32].copy_from_slice(recipient_ata);
    offset += 32;
    script[offset] = OP_DROP;
    offset += 1;
    script[offset] = 0x50 + MANAGER_CUSTODY_THRESHOLD;
    offset += 1;
    for public_key in MANAGER_CUSTODY_PUBLIC_KEYS {
        script[offset] = OP_PUSHBYTES_33;
        offset += 1;
        script[offset..offset + 33].copy_from_slice(&public_key);
        offset += 33;
    }
    script[offset] = 0x50 + MANAGER_CUSTODY_KEY_COUNT as u8;
    offset += 1;
    script[offset] = OP_CHECKMULTISIG;
    offset += 1;
    debug_assert_eq!(offset, MANAGER_CUSTODY_REDEEM_SCRIPT_SIZE);

    script
}

pub fn get_manager_custody_address_hash(
    custody_script_config: &CustodyScriptConfig,
    recipient_ata: &[u8; 32],
) -> [u8; 20] {
    QBTCHash160Hasher::hash_bytes(&get_manager_custody_redeem_script(
        custody_script_config,
        recipient_ata,
    ))
}

pub fn get_manager_custody_output_script(
    custody_script_config: &CustodyScriptConfig,
    recipient_ata: &[u8; 32],
) -> [u8; 23] {
    gen_p2sh_script(&get_manager_custody_address_hash(
        custody_script_config,
        recipient_ata,
    ))
}

pub fn is_manager_custody_output_for_recipient(
    output: &BTCTransactionOutput,
    custody_script_config: &CustodyScriptConfig,
    recipient_ata: &[u8; 32],
) -> bool {
    output.script == get_manager_custody_output_script(custody_script_config, recipient_ata)
}

#[cfg(test)]
mod manager_custody_tests {
    use super::*;
    use speedy::Writable;

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

    #[test]
    fn exact_manager_script_matches_deposit_to_solana_shape() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let script = get_manager_custody_redeem_script(&config, &RECIPIENT_ATA);

        assert_eq!(script.len(), 312);
        assert_eq!(&script[..4], &[0x02, 0x00, 0x01, 0x20]);
        assert_eq!(&script[4..36], &BRIDGE_STATE_PDA);
        assert_eq!(script[36], OP_2DROP);
        assert_eq!(script[37], OP_PUSHBYTES_32);
        assert_eq!(&script[38..70], &RECIPIENT_ATA);
        assert_eq!(script[70], OP_DROP);
        assert_eq!(script[71], 0x55);
        for (index, public_key) in MANAGER_CUSTODY_PUBLIC_KEYS.iter().enumerate() {
            let offset = 72 + index * 34;
            assert_eq!(script[offset], OP_PUSHBYTES_33);
            assert_eq!(&script[offset + 1..offset + 34], public_key);
        }
        assert_eq!(&script[310..], &[0x57, OP_CHECKMULTISIG]);
        assert_eq!(
            get_manager_custody_output_script(&config, &RECIPIENT_ATA),
            hex_literal::hex!("a914e82fee979cd3f155a2a073040936e98ce807a47e87")
        );
        assert_eq!(
            get_manager_custody_output_script(&config, &RECIPIENT_ATA),
            gen_p2sh_script(&QBTCHash160Hasher::hash_bytes(&script))
        );
    }

    #[test]
    fn mutated_emitter_or_recipient_changes_output_script() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        let expected = get_manager_custody_output_script(&config, &RECIPIENT_ATA);

        let mut emitter = BRIDGE_STATE_PDA;
        emitter[0] ^= 1;
        assert_ne!(
            get_manager_custody_output_script(&CustodyScriptConfig::new(emitter), &RECIPIENT_ATA),
            expected
        );

        let mut recipient = RECIPIENT_ATA;
        recipient[31] ^= 1;
        assert_ne!(get_manager_custody_output_script(&config, &recipient), expected);
    }

    #[test]
    fn mutated_key_or_threshold_is_rejected() {
        let mut keys = MANAGER_CUSTODY_PUBLIC_KEYS;
        keys[3][7] ^= 1;
        assert!(CustodyScriptConfig::try_from_manager_set(
            BRIDGE_STATE_PDA,
            MANAGER_CUSTODY_THRESHOLD,
            &keys,
        )
        .is_err());
        assert!(CustodyScriptConfig::try_from_manager_set(
            BRIDGE_STATE_PDA,
            MANAGER_CUSTODY_THRESHOLD - 1,
            &MANAGER_CUSTODY_PUBLIC_KEYS,
        )
        .is_err());
    }

    #[test]
    fn config_preimage_and_hash_are_exact() {
        let config = CustodyScriptConfig::new(BRIDGE_STATE_PDA);
        assert_eq!(config.to_preimage_bytes(), BRIDGE_STATE_PDA);
        assert_eq!(
            config.hash(),
            hex_literal::hex!("afae9579f67ecff79ea3297a58a4c814a4582020abd4e6d3f5e3b19b46f1ab69")
        );
        assert_eq!(borsh::to_vec(&config).unwrap(), BRIDGE_STATE_PDA);
        assert_eq!(config.write_to_vec().unwrap(), BRIDGE_STATE_PDA);
    }
}

pub fn is_bridge_desposit_output_v1_for_user(
    output: &BTCTransactionOutput,
    user_public_key: &[u8],
    bridge_public_key_hash: &[u8],
) -> bool {
    if output.is_p2sh_output() {
        let output_addr: [u8; 20] = output.script[2..22].try_into().unwrap();
        get_bridge_deposit_address_hash_v1(user_public_key, bridge_public_key_hash) == output_addr
    } else {
        false
    }
}
