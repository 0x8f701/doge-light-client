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

use crate::common_types::QHash256;

const DIFFICULTY_NEGATIVE_FLAG: u32 = 0x00800000;
fn find_first_non_zero_index(x: [u8; 32]) -> i32 {
    for i in 0..32 {
        if x[i] != 0 {
            return i as i32;
        }
    }
    -1
}
fn num_bits_u256_be_and_first_non_zero_index(x: [u8; 32]) -> (usize, usize) {
    let first_non_zero_ind = find_first_non_zero_index(x);
    if first_non_zero_ind == -1 {
        (0, 0)
    } else {
        let bits = (32 - first_non_zero_ind as usize) * 8
            - x[first_non_zero_ind as usize].leading_zeros() as usize;
        (bits, first_non_zero_ind as usize)
    }
}

fn num_bits_u256_be_and_high_u32(x: [u8; 32]) -> (usize, u32) {
    let (bits, first_non_zero_ind) = num_bits_u256_be_and_first_non_zero_index(x);
    if bits == 0 {
        (0, 0)
    } else {
        let h_u32 = if first_non_zero_ind + 4 <= 32 {
            u32::from_be_bytes([
                x[first_non_zero_ind],
                x[first_non_zero_ind + 1],
                x[first_non_zero_ind + 2],
                x[first_non_zero_ind + 3],
            ])
        } else if first_non_zero_ind + 3 <= 32 {
            u32::from_be_bytes([
                0,
                x[first_non_zero_ind],
                x[first_non_zero_ind + 1],
                x[first_non_zero_ind + 2],
            ])
        } else if first_non_zero_ind + 2 <= 32 {
            u32::from_be_bytes([0, 0, x[first_non_zero_ind], x[first_non_zero_ind + 1]])
        } else {
            u32::from_be_bytes([0, 0, 0, x[first_non_zero_ind]])
        };
        (bits, h_u32)
    }
}
fn reduce_exponent_unsigned(exponent: u32, significand: u32) -> (u32, u32) {
    if exponent == 0 || significand == 0 {
        (0, significand)
    } else if (significand & 0xff0000) != 0 {
        (exponent, significand)
    } else if (significand & 0x00ff00) != 0 {
        (exponent - 1, significand << 8)
    } else if (significand & 0x0000ff) != 0 {
        if exponent >= 2 {
            (exponent - 2, significand >> 16)
        } else {
            (exponent - 1, significand >> 8)
        }
    } else {
        (exponent, significand)
    }
}
fn get_extra_precision_64(
    exponent: u32,
    shifted_significand: u64,
    negative: bool,
) -> BTCDifficulty {
    if shifted_significand == 0 {
        let n_sig = shifted_significand as u32;
        BTCDifficulty::from_parts(0, n_sig, negative).to_lowest_exponent_form()
    } else if exponent == 0 && shifted_significand <= 0xffffffff {
        BTCDifficulty::from_parts(0, 0, negative).to_lowest_exponent_form()
    } else {
        //let shifted_sig_bits  = (64 - shifted_significand.leading_zeros());
        let mut x = shifted_significand;
        let mut new_exponent = exponent;

        if x > 0x7fffffffffffffffu64 {
            x >>= 8;
            new_exponent += 1;
        }

        while x < 0x00ffffffffffffffu64 && new_exponent > 0 {
            x <<= 8;
            new_exponent -= 1;
        }

        if x > 0x7fffffffffffffffu64 {
            x >>= 8;
            new_exponent += 1;
        }

        let mut base_p = (x >> 32) as u64;
        while base_p > 0x7fffff {
            base_p >>= 8;
            new_exponent += 1;
        }
        BTCDifficulty::from_parts(new_exponent, base_p as u32, negative).to_lowest_exponent_form()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BTCDifficulty(u32);
impl BTCDifficulty {
    pub fn get_exponent(&self) -> u32 {
        self.0 >> 24
    }
    pub fn is_negative(&self) -> bool {
        self.0 & DIFFICULTY_NEGATIVE_FLAG != 0
    }
    pub fn get_negative_sign_bit_flag(&self) -> u32 {
        self.0 & DIFFICULTY_NEGATIVE_FLAG
    }
    pub fn get_significand(&self) -> u32 {
        self.0 & 0x007fffff
    }
    pub fn mul_value(&self, value: u32) -> Self {
        if value == 0 {
            return BTCDifficulty(0);
        } else if value == 1 {
            return BTCDifficulty(self.0);
        } else if self.is_zero() {
            return BTCDifficulty(0);
        }

        let significand = self.get_significand();
        let exponent = self.get_exponent();
        let negative = self.is_negative();
        let n_sig = (significand as u64) * (value as u64);
        if n_sig <= 0x007fffff {
            BTCDifficulty::from_parts(exponent, n_sig as u32, negative).to_lowest_exponent_form()
        } else {
            let n_sig = n_sig >> 8;
            let n_exp = exponent + 1;
            BTCDifficulty::from_parts(n_exp, n_sig as u32, negative).to_lowest_exponent_form()
        }
    }
    pub fn div_value(&self, value: u32) -> Self {
        if value == 0 {
            // infinity?
            return BTCDifficulty(0);
        } else if value == 1 {
            return BTCDifficulty(self.0);
        } else if self.is_zero() {
            return BTCDifficulty(0);
        }

        let significand = self.get_significand();
        let exponent = self.get_exponent();
        let negative = self.is_negative();
        let n_sig = ((((significand as u64) << 32) / (value as u64)) >> 32) as u32;
        if n_sig <= 0x007fffff {
            BTCDifficulty::from_parts(exponent, n_sig as u32, negative).to_lowest_exponent_form()
        } else {
            let n_sig = n_sig >> 8;
            let n_exp = exponent + 1;
            BTCDifficulty::from_parts(n_exp, n_sig as u32, negative).to_lowest_exponent_form()
        }
    }
    pub fn new_from_hash(hash: QHash256) -> Self {
        let (n_bits, high_u32) = num_bits_u256_be_and_high_u32(hash);

        let mut n_size = ((n_bits as u32) + 7) / 8;
        let mut n_compact = 0u32;
        if n_size <= 3 {
            n_compact = high_u32 << 8 * (3 - n_size);
        } else {
            // Bitcoin Core GetCompact: take the top 3 bytes of the value
            // (high_u32 holds the top 4 bytes; shifting right by 8 drops the
            // least-significant of those four, leaving the top 3 bytes).
            n_compact = high_u32 >> 8;
        }
        n_compact &= 0x00ffffff;
        // The 0x00800000 bit denotes the sign.
        // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
        if (n_compact & DIFFICULTY_NEGATIVE_FLAG) != 0 {
            n_compact = n_compact >> 8;
            n_size += 1;
        }
        n_compact |= n_size << 24;
        BTCDifficulty(n_compact)
    }
    pub fn new_from_bits(compact: u32) -> Self {
        Self(compact)
    }
    pub fn get_str(&self) -> String {
        let exponent = self.get_exponent();
        let significand = self.get_significand();
        let negative = self.is_negative();
        format!(
            "exponent: {}, significand: {}, negative: {}",
            exponent, significand, negative
        )
    }
    pub fn is_zero(&self) -> bool {
        self.0 & 0x007fffff == 0
    }
    pub fn from_parts(exponent: u32, significand: u32, negative: bool) -> Self {
        let sign_flag = if negative {
            DIFFICULTY_NEGATIVE_FLAG
        } else {
            0
        };
        Self((exponent << 24) | sign_flag | significand)
    }
    pub fn to_lowest_exponent_form(&self) -> Self {
        let current = self.0;
        if current == 0 || current & 0x007f0000 != 0 || self.get_exponent() == 0 {
            Self(current)
        } else {
            let exponent = self.get_exponent();
            let significand = self.get_significand();
            let sign_bit_flag = self.get_negative_sign_bit_flag();
            let low_16 = significand & 0xffff;

            if significand == 0 {
                Self(sign_bit_flag)
            } else if (low_16 & 0xff00) != 0 {
                if low_16 == (low_16 & 0x7fff) {
                    // it is safe to shift up by 8 bits since it will not disturb the sign bit
                    Self::from_parts(exponent - 1, significand << 8, self.is_negative())
                } else {
                    // we can't shift the significand by 8 bits if it would interfere with the sign bit
                    Self(current)
                }
            } else {
                let low_byte = low_16 & 0xff;
                if low_byte == (low_byte & 0x7f) && exponent >= 2 {
                    // it is safe to shift up by 16 bits since it will not disturb the sign bit
                    Self::from_parts(exponent - 2, significand << 16, self.is_negative())
                } else {
                    Self::from_parts(exponent - 1, significand << 8, self.is_negative())
                }
            }
        }
    }
    pub fn is_greater_than(&self, other: &Self) -> bool {
        if self.is_negative() && !other.is_negative() {
            false
        } else if !self.is_negative() && other.is_negative() {
            true
        } else {
            let (self_exp, self_sig) =
                reduce_exponent_unsigned(self.get_exponent(), self.get_significand());
            let (other_exp, other_sig) =
                reduce_exponent_unsigned(other.get_exponent(), other.get_significand());
            if self_exp > other_exp {
                true
            } else if self_exp < other_exp {
                false
            } else {
                self_sig > other_sig
            }
        }
    }
    pub fn is_equal_to(&self, other: &Self) -> bool {
        self.to_lowest_exponent_form().0 == other.to_lowest_exponent_form().0
    }
    pub fn new_from_bits_0_if_overflow(compact: u32) -> Self {
        let n_size = compact >> 24;
        let n_word = if n_size <= 3 {
            (compact & 0x007fffff) >> (8 * (3 - n_size))
        } else {
            compact & 0x007fffff
        };

        let negative = n_word != 0 && compact & DIFFICULTY_NEGATIVE_FLAG != 0;
        let overflow = n_word != 0
            && ((n_size > 34)
                || (n_word > 0xff && n_size > 33)
                || (n_word > 0xffff && n_size > 32));

        if negative || overflow {
            BTCDifficulty(0)
        } else {
            BTCDifficulty(compact)
        }
    }
    pub fn to_compact_bits(&self) -> u32 {
        self.0
    }
    pub fn is_leq(&self, other: &Self) -> bool {
        !self.is_greater_than(other)
    }
    pub fn is_geq(&self, other: &Self) -> bool {
        self.is_greater_than(other) || self.is_equal_to(other)
    }
    pub fn is_gt(&self, other: &Self) -> bool {
        self.is_greater_than(other)
    }
    pub fn to_adjust_for_next_work(&self, modulated_timespan: i64, retarget_timespan: i64) -> Self {
        let exponent = self.get_exponent();
        let significand = self.get_significand();

        if exponent == 0 {
            let mul_res = (((((significand as u128) * (modulated_timespan as u128)) << 32)
                / (retarget_timespan as u128))
                >> 32) as u32;
            let negative = self.is_negative();
            if mul_res <= 0x007fffff {
                BTCDifficulty::from_parts(exponent, mul_res, negative).to_lowest_exponent_form()
            } else {
                let n_sig = mul_res >> 8;
                let n_exp = exponent + 1;
                BTCDifficulty::from_parts(n_exp, n_sig as u32, negative).to_lowest_exponent_form()
            }
        } else {
            let sig_mul_res = (significand as u64) * (modulated_timespan as u64);
            if sig_mul_res > 0xffff_ffffu64 {
                let mut smr_shifted = sig_mul_res;
                let mut shift_positions = 0;
                while smr_shifted < 0x00ff_ffff_ffff_ffffu64 && shift_positions < 4 {
                    smr_shifted <<= 8;
                    shift_positions += 1;
                }
                let sig_div_1 = smr_shifted / (retarget_timespan as u64);
                get_extra_precision_64(
                    exponent + (4 - shift_positions),
                    sig_div_1,
                    self.is_negative(),
                )
            } else {
                let sig_div_1 = (sig_mul_res << 32) / (retarget_timespan as u64);
                get_extra_precision_64(exponent, sig_div_1, self.is_negative())
            }
        }
    }
    pub fn into_adjust_for_next_work(
        &self,
        modulated_timespan: i64,
        retarget_timespan: i64,
        pow_limit: &Self,
    ) -> u32 {
        let res = self.to_adjust_for_next_work(modulated_timespan, retarget_timespan);
        if res.is_geq(pow_limit) {
            pow_limit.to_compact_bits()
        } else {
            res.to_compact_bits()
        }
    }
}

#[cfg(test)]
mod test {
    use rand::{thread_rng, Rng};

    fn get_extra_precision_128(
        exponent: u32,
        shifted_significand: u128,
        negative: bool,
    ) -> BTCDifficulty {
        if shifted_significand == 0 {
            let n_sig = shifted_significand as u32;
            BTCDifficulty::from_parts(0, n_sig, negative).to_lowest_exponent_form()
        } else if exponent == 0 && shifted_significand <= 0xffffffff {
            BTCDifficulty::from_parts(0, 0, negative).to_lowest_exponent_form()
        } else {
            //let shifted_sig_bits  = (64 - shifted_significand.leading_zeros());
            let mut x = shifted_significand;
            let mut new_exponent = exponent;

            if x > 0x7fffffffffffffffffffffffffffffffu128 {
                x >>= 8;
                new_exponent += 1;
            }

            while x < 0x00ffffffffffffffffffffffffffffffu128 && new_exponent > 0 {
                x <<= 8;
                new_exponent -= 1;
            }

            if x > 0x7fffffffffffffffffffffffffffffffu128 {
                x >>= 8;
                new_exponent += 1;
            }

            let mut base_p = (x >> 64) as u64;
            while base_p > 0x7fffff {
                base_p >>= 8;
                new_exponent += 1;
            }
            BTCDifficulty::from_parts(new_exponent, base_p as u32, negative)
                .to_lowest_exponent_form()
        }
    }

    fn to_adjust_for_next_work_u128(
        x: BTCDifficulty,
        modulated_timespan: i64,
        retarget_timespan: i64,
    ) -> BTCDifficulty {
        let exponent = x.get_exponent();
        let significand = x.get_significand();

        if exponent == 0 {
            let mul_res = (((((significand as u128) * (modulated_timespan as u128)) << 32)
                / (retarget_timespan as u128))
                >> 32) as u32;
            let negative = x.is_negative();
            if mul_res <= 0x007fffff {
                BTCDifficulty::from_parts(exponent, mul_res, negative).to_lowest_exponent_form()
            } else {
                let n_sig = mul_res >> 8;
                let n_exp = exponent + 1;
                BTCDifficulty::from_parts(n_exp, n_sig as u32, negative).to_lowest_exponent_form()
            }
        } else {
            let sig_mul_res = (significand as u64) * (modulated_timespan as u64);
            let sig_div_1 = ((sig_mul_res as u128) << 64) / (retarget_timespan as u128);
            get_extra_precision_128(exponent, sig_div_1, x.is_negative())
        }
    }

    use super::BTCDifficulty;

    fn check_one_128_u64() -> anyhow::Result<()> {
        let s = thread_rng().gen_range(0..=0x7fffffu32);
        let e = thread_rng().gen_range(0..=0x20u32);
        let d1 = BTCDifficulty::from_parts(e, s, false);
        let modulated_timespan = thread_rng().gen_range(0..=0x7fffffffu64);
        let retarget_timespan = thread_rng().gen_range(1..=0xfffffu64);
        let new_v = d1.to_adjust_for_next_work(modulated_timespan as i64, retarget_timespan as i64);
        let old_v =
            to_adjust_for_next_work_u128(d1, modulated_timespan as i64, retarget_timespan as i64);

        assert_eq!(new_v.0, old_v.0);
        Ok(())
    }
    #[test]
    fn test_fuzz_128_64() -> anyhow::Result<()> {
        for i in 0..100 {
            println!("checking {}", i * 1000);
            for _ in 0..1000 {
                check_one_128_u64()?;
            }
        }

        Ok(())
    }

    /// B10 (fixed): `new_from_hash` previously zeroed the compact significand for
    /// any hash whose byte-length (`n_size`) exceeded 3, because the `else` arm
    /// only did `n_compact >>= 8` on an already-zero value and never read
    /// `high_u32`. After the fix it follows Bitcoin Core `GetCompact`: it takes
    /// the top 3 bytes of the value (`high_u32 >> 8`) and applies sign-bit
    /// normalization. These tests pin the corrected behaviour against reference
    /// vectors computed from Bitcoin Core's `GetCompact`.
    #[test]
    fn b10_new_from_hash_all_ones_not_zero() {
        // all-ones hash: bits=256, n_size=32, top 3 bytes = 0xffffff.
        // 0xffffff has the sign bit (0x00800000) set, so Core shifts right by 8
        // (significand -> 0xffff) and bumps the exponent to 33 -> 0x2100ffff.
        let all_ones = [0xffu8; 32];
        let d = BTCDifficulty::new_from_hash(all_ones);
        assert!(
            !d.is_zero(),
            "B10 regression: all-ones hash collapsed to zero difficulty; compact={:#010x}",
            d.0
        );
        assert_eq!(
            d.0,
            0x2100ffff,
            "all-ones compact must match Bitcoin Core GetCompact (0x2100ffff); got {:#010x}",
            d.0
        );
        assert_eq!(d.get_exponent(), 0x21);
        assert_eq!(d.get_significand(), 0xffff);
        assert!(!d.is_negative());
    }

    #[test]
    fn b10_new_from_hash_zero_hash_is_zero() {
        // The zero hash maps to compact 0 (the hardest possible target). This
        // must remain zero after the fix; it must not regress into a non-zero
        // significand via the n_size>3 path.
        let d = BTCDifficulty::new_from_hash([0u8; 32]);
        assert!(d.is_zero(), "zero hash must be zero difficulty; compact={:#010x}", d.0);
        assert_eq!(d.0, 0x00000000);
    }

    /// Reference vectors for `new_from_hash` against Bitcoin Core `GetCompact`.
    /// Each hash is a big-endian 32-byte array holding only the low `n` bytes.
    fn make_hash(low_bytes: &[u8]) -> [u8; 32] {
        let mut h = [0u8; 32];
        let n = low_bytes.len();
        h[32 - n..].copy_from_slice(low_bytes);
        h
    }

    #[test]
    fn b10_new_from_hash_matches_bitcoin_core_reference_vectors() {
        // (low_bytes, expected compact). Compact computed by Bitcoin Core
        // GetCompact for the 256-bit big-endian value formed by `low_bytes`.
        let cases: &[(&[u8], u32)] = &[
            // 1-byte value 0x12: n_size=1, sig = 0x12<<16 = 0x120000.
            (&[0x12u8], 0x01120000),
            // 1-byte value 0xff (top bit set): sign-shift -> sig 0xff00, exp 2.
            (&[0xffu8], 0x0200ff00),
            // 2-byte value 0x1234: n_size=2, sig = 0x1234<<8 = 0x123400.
            (&[0x12u8, 0x34], 0x02123400),
            // 3-byte value 0x123456: n_size=3, sig = 0x123456 (no shift).
            (&[0x12u8, 0x34, 0x56], 0x03123456),
            // 3-byte value 0x80ff00 (top bit set): sign-shift -> sig 0x80ff, exp 4.
            (&[0x80u8, 0xff, 0x00], 0x040080ff),
            // 4-byte value 0x12345678: n_size=4, top 3 bytes = 0x123456.
            (&[0x12u8, 0x34, 0x56, 0x78], 0x04123456),
            // 4-byte value 0xffffffff (top bit set after >>8): sig 0xffffff ->
            //   sign-shift -> sig 0xffff, exp 5.
            (&[0xffu8, 0xff, 0xff, 0xff], 0x0500ffff),
            // 5-byte value 0xff_ffffffff: n_size=5, top3 = 0xffffff -> sign-shift
            //   -> sig 0xffff, exp 6.
            (&[0xffu8, 0xff, 0xff, 0xff, 0xff], 0x0600ffff),
            // Dogecoin mainnet/testnet pow_limit hash
            // "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            // (bytes: 00 00 0f ff ... ff): n_size=30, top3=0x0fffff -> 0x1e0fffff.
            (
                &hex_literal::hex!("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                0x1e0fffff,
            ),
            // all-ones (256 bits): n_size=32, top3=0xffffff -> sign-shift
            //   -> sig 0xffff, exp 33 -> 0x2100ffff.
            (&[0xffu8; 32], 0x2100ffff),
        ];

        for (i, (bytes, expected)) in cases.iter().enumerate() {
            let h = if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                arr
            } else {
                make_hash(bytes)
            };
            let d = BTCDifficulty::new_from_hash(h);
            assert_eq!(
                d.0, *expected,
                "vec[{}]: bytes={:02x?} expected compact {:#010x} got {:#010x}",
                i, bytes, expected, d.0,
            );
        }
    }

    #[test]
    fn b10_new_from_hash_sign_bit_normalization() {
        // A significand whose high byte sets the 0x00800000 sign bit must be
        // renormalized by shifting right 8 and incrementing the exponent, never
        // by leaving the sign bit set in the stored compact.
        let mut h = [0u8; 32];
        h[29] = 0x80;
        h[30] = 0xff;
        h[31] = 0x00;
        let d = BTCDifficulty::new_from_hash(h);
        assert_eq!(d.0, 0x040080ff, "sign-bit normalization vec; got {:#010x}", d.0);
        assert!(
            !d.is_negative(),
            "a positive hash must never be flagged negative; compact={:#010x}",
            d.0
        );
        // The high byte of the significand must not retain the sign bit.
        assert_eq!(d.get_significand() & 0xff0000, 0x008000 & 0xff0000);
    }

    /// B10 consequence via the real PoW gate: all-ones hash must be rejected
    /// against the Dogecoin mainnet difficulty at height ~145001.
    #[test]
    fn b10_check_proof_of_work_must_reject_all_ones_mainnet() {
        use crate::constants::DogeMainNetConfig;
        use crate::logic::check_doge_block_seq::check_proof_of_work;

        let n_bits: u32 = 0x1b671062;
        let all_ones = [0xffu8; 32];
        let accepted = check_proof_of_work::<DogeMainNetConfig>(all_ones, n_bits);
        assert!(
            !accepted,
            "all-ones PoW hash ACCEPTED against mainnet n_bits={:#x} (consensus bypass)",
            n_bits
        );
    }

    /// Same B10 nail against `DogeTestNetConfig` (the E2E network profile): the
    /// all-ones hash must be rejected against the testnet min-difficulty target.
    #[test]
    fn b10_check_proof_of_work_must_reject_all_ones_testnet() {
        use crate::constants::{DogeNetworkConfig, DogeTestNetConfig};
        use crate::logic::check_doge_block_seq::check_proof_of_work;

        // testnet pow_limit = 504365055 = 0x1e0fffff (same as mainnet).
        let n_bits: u32 = DogeTestNetConfig::NETWORK_PARAMS.pow_limit;
        assert_eq!(n_bits, 0x1e0fffff, "testnet pow_limit sanity");
        let all_ones = [0xffu8; 32];
        let accepted = check_proof_of_work::<DogeTestNetConfig>(all_ones, n_bits);
        assert!(
            !accepted,
            "all-ones PoW hash ACCEPTED against testnet pow_limit={:#x} (consensus bypass)",
            n_bits
        );
        // Sanity: a hash strictly below the testnet pow_limit target is accepted.
        // pow_limit compact = 0x1e0fffff -> target = 0x0fffff << 216 (~2^236).
        // `check_proof_of_work` reverses the little-endian input before reading
        // it as a big-endian uint256, so to build a *small* big-endian value the
        // least-significant byte must sit at input index 0. value 0x42 is far
        // below the target and must be accepted by the PoW gate.
        let mut easy = [0u8; 32];
        easy[0] = 0x42;
        let accepted_easy = check_proof_of_work::<DogeTestNetConfig>(easy, n_bits);
        assert!(
            accepted_easy,
            "easy hash (value 0x42) below testnet pow_limit target was REJECTED; pow_limit={:#x}",
            n_bits
        );
    }
}
