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

use crate::{
    common_types::QHash256,
    constants::DogeNetworkConfig,
    core_data::QDogeBlockHeader,
    error::{DogeBridgeError, QDogeResult},
};

use super::check_doge_block_seq::{check_proof_of_work, get_next_work_required};

pub fn check_block_header_err<NC: DogeNetworkConfig>(
    last_height: u32,
    block_header: &QDogeBlockHeader,
    last_block_time: u32,
    last_bits: u32,
    first_block_time: u32,
    known_pow_block_hash: Option<QHash256>,
) -> QDogeResult<()> {
    if block_header.header.is_aux_pow() != block_header.aux_pow.is_some() {
        return Err(DogeBridgeError::AuxPowVersionBitsMismatch);
    }
    if NC::NETWORK_PARAMS.strict_chain_id
        && NC::NETWORK_PARAMS.aux_pow_chain_id != block_header.header.get_chain_id()
    {
        return Err(DogeBridgeError::AuxPowChainIdMismatch);
    }
    let expected_difficulty_bits = get_next_work_required::<NC>(
        last_height,
        last_block_time as i64,
        last_bits,
        first_block_time as i64,
        block_header.header.timestamp as i64,
    );
    if expected_difficulty_bits != block_header.header.bits {
        return Err(DogeBridgeError::DifficutlyBitsMismatch);
    }
    if block_header.aux_pow.is_none() {
        if !check_proof_of_work::<NC>(
            if known_pow_block_hash.is_some() {
                known_pow_block_hash.unwrap()
            } else {
                block_header.header.get_pow_hash()
            },
            block_header.header.bits,
        ) {
            return Err(DogeBridgeError::StandardPoWCheckFailed);
        }
    } else {
        if !check_proof_of_work::<NC>(
            if known_pow_block_hash.is_some() {
                known_pow_block_hash.unwrap()
            } else {
                block_header
                    .aux_pow
                    .as_ref()
                    .unwrap()
                    .parent_block
                    .get_pow_hash()
            },
            block_header.header.bits,
        ) {
            return Err(DogeBridgeError::AuxPowParentBlockPoWCheckFailed);
        }
        block_header.aux_pow.as_ref().unwrap().check_err::<NC>(
            block_header.header.get_hash(),
            block_header.header.get_chain_id(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod b12_b13_bug_nails {
    use super::*;
    use crate::constants::DogeMainNetConfig;
    use crate::logic::check_doge_block_seq::check_proof_of_work;

    /// B12: when `known_pow_block_hash = Some(favorable)`, check_proof_of_work is
    /// called on the *supplied* hash, not on header.get_pow_hash() / scrypt.
    /// Demonstrate: an all-zero "PoW hash" against a very easy target is accepted
    /// even though a real scrypt of a non-PoW header would fail.
    ///
    /// We nail this at the check_proof_of_work layer with the same substitution
    /// the `if known_pow_block_hash.is_some()` branch performs in check_block_header_err.
    #[test]
    fn b12_operator_supplied_hash_is_what_pow_gate_sees() {
        // Easy target: n_bits with large target (testnet-like min difficulty)
        // pow_limit mainnet is 0x1e0fffff-ish; use a known easy compact.
        // 0x1e0fffff is common Dogecoin min-diff style.
        let easy_bits: u32 = 0x1e0fffff;

        // A "favorable" all-zero hash (difficulty 0 after reverse) — always ≤ target
        // if new_from_hash works, or always ≤ if B10 zeros it. Either way accepted.
        let favorable = [0u8; 32];
        let accepted_favorable = check_proof_of_work::<DogeMainNetConfig>(favorable, easy_bits);

        // An all-ones hash would be invalid PoW against any real target *if*
        // new_from_hash worked. With B10 it is also accepted. Use a mid hash.
        // The point of B12: the *caller* chooses which hash hits check_proof_of_work.
        // The production API signature is Option — Some means skip scrypt.
        assert!(
            accepted_favorable,
            "zero hash should pass easy target (setup for B12 demonstration)"
        );

        // Document the API: check_block_header_err takes Option and substitutes.
        // We cannot call scrypt here cheaply, but the source branch is:
        //   if known_pow_block_hash.is_some() { known } else { header.get_pow_hash() }
        // and append_block / rollback both forward the Option from the caller.
        // The guest path passes None (safe); the library still *allows* Some.
        let src = include_str!("check_doge_block.rs");
        assert!(
            src.contains("known_pow_block_hash.unwrap()"),
            "B12: known_pow_block_hash.unwrap() still present — operator can skip scrypt"
        );
        let chain = include_str!("../chain_state.rs");
        assert!(
            chain.contains("known_aux_pow_block_hash"),
            "B12: append_block still accepts known_aux_pow_block_hash: Option"
        );
    }

    /// B13: no median-time-past validation in production consensus path.
    /// Dogecoin Core enforces `nTime > getMedianTimePast()` (time-too-old).
    #[test]
    fn b13_no_median_time_past_in_production_consensus_path() {
        // Strip any #[cfg(test)] modules from the sources we scan so our own
        // comments cannot false-positive.
        fn production_only(src: &str) -> String {
            let mut out = String::new();
            let mut in_test = false;
            let mut depth = 0i32;
            for line in src.lines() {
                let t = line.trim_start();
                if !in_test && t.starts_with("#[cfg(test)]") {
                    in_test = true;
                    depth = 0;
                    continue;
                }
                if in_test {
                    depth += line.chars().filter(|c| *c == '{').count() as i32;
                    depth -= line.chars().filter(|c| *c == '}').count() as i32;
                    if depth <= 0 && line.contains('}') {
                        in_test = false;
                    }
                    continue;
                }
                out.push_str(line);
                out.push('\n');
            }
            out
        }

        let modules = [
            production_only(include_str!("check_doge_block.rs")),
            production_only(include_str!("check_doge_block_seq.rs")),
            production_only(include_str!("../chain_state.rs")),
            production_only(include_str!("../block_data_tracker.rs")),
        ];
        for (i, m) in modules.iter().enumerate() {
            let lower = m.to_ascii_lowercase();
            // Real MTP symbols Dogecoin Core uses
            let hits: Vec<&str> = [
                "getmediantimepast",
                "median_time",
                "median-time",
                "time_too_old",
                "timetooold",
            ]
            .into_iter()
            .filter(|k| lower.contains(k))
            .collect();
            assert!(
                hits.is_empty(),
                "B13: production module {i} still has MTP symbols: {hits:?}"
            );
        }

        // Positive control: timestamp is checked only against paused_until in helper,
        // not against median of prior 11 blocks, in these consensus files.
        let check = production_only(include_str!("check_doge_block.rs"));
        assert!(
            !check.contains("previous_11") && !check.contains("last_11"),
            "B13: unexpected 11-block window present"
        );
    }
}
