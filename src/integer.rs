// MSecret
//
// Copyright 2023 Robert Quattlebaum
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::prelude_internal::*;

use num_bigint::BigUint;

#[cfg(feature = "openssl")]
use openssl::bn::BigNum;

/// Integer Derivation.
///
/// This trait contains methods for extracting integers with an arbitrary specified maximum value.
///
/// The distribution of the output over the interval `[0..=max]` is guaranteed to be uniform.
/// This uniformity is guaranteed by calculating the random value using `extract_bytes` and
/// then checking to see if it is less than or equal to `max`. If it is larger, we mutate
/// our seed and try again until we have a suitable number. An additional optimization
/// reduces the worst-case chances of a miss to %50 per iteration.
///
/// ## V1 Algorithm ##
///
/// Writeme.
pub trait ExtractInteger {
    /// Extracts a big-endian integer between zero and `max` into the byte-slice `out`.
    ///
    /// The distribution of the output over the interval `[0..max]` is guaranteed to be uniform.
    /// This uniformity is guaranteed by calculating the random value using `extract_bytes` and
    /// then checking to see if it is less than or equal to `max`. If it is larger, we mutate
    /// our seed and try again until we have a suitable number. An additional optimization
    /// reduces the worst-case chances of a miss to %50 per iteration.
    fn extract_int_to_be_slice(&self, max: &[u8], out: &mut [u8]) -> Result<()>;

    /// Extracts a big-endian integer between zero and `max`, returning it as `Vec<u8>`.
    fn extract_int_to_be_vec(&self, max: &[u8]) -> Result<Vec<u8>> {
        let mut ret = max.to_vec();
        self.extract_int_to_be_slice(max, &mut ret)?;
        Ok(ret)
    }

    /// Extracts an [`u64`] integer between zero and `max`.
    fn extract_u64(&self, max: u64) -> Result<u64> {
        let max = max.to_be_bytes();
        let mut ret = max;
        self.extract_int_to_be_slice(&max, &mut ret)?;
        Ok(u64::from_be_bytes(ret))
    }

    /// Extracts an [`usize`] integer between zero and `max`.
    fn extract_usize(&self, max: usize) -> Result<usize> {
        let max = max.to_be_bytes();
        let mut ret = max;
        self.extract_int_to_be_slice(&max, &mut ret)?;
        Ok(usize::from_be_bytes(ret))
    }

    /// Extracts an [`u32`] integer between zero and `max`.
    fn extract_u32(&self, max: u32) -> Result<u32> {
        Ok(self.extract_usize(max as usize)?.try_into().unwrap())
    }

    /// Extracts a [`bool`].
    fn extract_bool(&self) -> Result<bool> {
        Ok(self.extract_u32(1)? == 1)
    }

    /// Extracts a [`BigUint`] integer between zero and `max`.
    fn extract_big_uint(&self, max: &BigUint) -> Result<BigUint> {
        Ok(BigUint::from_bytes_be(
            &self.extract_int_to_be_vec(&max.to_bytes_be())?,
        ))
    }

    /// Extracts an [`openssl::bn::BigNum`] integer between zero and `max`.
    #[cfg(feature = "openssl")]
    fn extract_big_num(&self, max: &BigNum) -> Result<BigNum> {
        Ok(BigNum::from_slice(
            &self.extract_int_to_be_vec(&max.to_vec())?,
        )?)
    }
}

impl ExtractInteger for Secret {
    fn extract_int_to_be_slice(&self, mut max: &[u8], mut out: &mut [u8]) -> Result<()> {
        // Sanity check.
        if max.len() != out.len() {
            bail!("slices must be the same size");
        }

        // We will mutate our secret iteratively as we find
        // a suitable random number, so we go ahead and clone
        // ourselves.
        let mut secret = self.clone();

        // Skip leading zero bytes, also marking them as
        // zero in the output buffer.
        while max.first() == Some(&0) {
            // Set the corresponding byte in the output to zero.
            out[0] = 0;

            // Shrink the slices from the head.
            out = &mut out[1..];
            max = &max[1..];
        }

        if max.is_empty() {
            // A random integer between zero and zero is going to be zero.
            return Ok(());
        }

        // Helper function for calculating the enclosing mask
        // for a given value. For example, for the value 48,
        // the output would be 63. We use this as a performance
        // optimization to reduce the number of retries.
        fn enclosing_mask_u8(mut x: u8) -> u8 {
            x |= x >> 1;
            x |= x >> 2;
            x |= x >> 4;
            x
        }

        let enclosing_mask = enclosing_mask_u8(max[0]);

        loop {
            // Mutate the secret with the maximum value.
            // This helps ensure that we get very different
            // values even for similar maximum values.
            // We also need to change the secret every time
            // we loop through this code, otherwise we would
            // loop infinitely.
            secret.mutate_with_salt(max)?;

            // Fill `out` with pseudorandom data.
            secret.extract_bytes_into(out)?;

            // Mask out any unused most-significant bits
            // in the first byte of `out`. This helps reduce
            // the worst-case performance enormously.
            //
            // Note that this optimization is REQUIRED by
            // the algorithm being used here. Removing this
            // will cause the returned numbers to be different,
            // in addition to hurting performance.
            out[0] &= enclosing_mask;

            // Check to see if the number we generated is
            // less than or equal to the max. If it isn't,
            // then we will need to try again.
            if (out as &[u8]) <= max {
                return Ok(());
            }
        }
    }
}
