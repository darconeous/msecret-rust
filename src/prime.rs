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

#[cfg(feature = "openssl")]
use openssl::bn::{BigNum, BigNumContext};

/// Prime Number Derivation.
///
/// ## V1 Algorithm ##
///
/// The underlying secret is first mutated with the salt `"\x00Prime_v1"`.
/// The bit-length is converted to the maximum numeric value by calculating
/// `(1<<bit_length)-1`. We then use this number to derive a random
/// integer from the mutated secret using the "MSecret Integer V1" algorithm.
///
/// We then take the random integer and ensure that the least significant
/// bit and two most significant bits are all set to 1. We then enter the
/// following loop:
///
/// 1. Check to see if the integer is prime, according to the primality
///    test outlined below.
/// 2. If the integer is not prime, increment the integer by two and
///    jump to step 1.
///
/// ## Primality Test ##
///
/// The primality test is defined to be a combination of the following:
///
/// * The FIPS 186-4 C.3.1 Miller-Rabin test
/// * The Baillie-PSW test
///
/// If both tests indicate the number is prime, then it is returned by this method.
/// In practice, the `is_prime` method in common crypto libraries is adequate.
pub trait ExtractPrimeV1 {
    /// Extracts a prime number of `bit_length` as an OpenSSL [`BigNum`].
    #[cfg(feature = "openssl")]
    fn extract_prime_v1_bignum(&self, bit_length: u16) -> Result<BigNum>;

    /// Extracts a prime number of `bit_length` as a [`num_bigint::BigUint`].
    fn extract_prime_v1_big_uint(&self, bit_length: u16) -> Result<num_bigint::BigUint>;
}

impl ExtractPrimeV1 for Secret {
    #[cfg(feature = "openssl")]
    fn extract_prime_v1_bignum(&self, bit_length: u16) -> Result<BigNum> {
        const SALT: &[u8] = b"\x00Prime_v1";
        let msecret = self.subsecret_from_salt(SALT)?;
        let mut ctx = BigNumContext::new_secure()?;

        // The algorithm we are using doesn't really work for small bit sizes,
        // so we fail if the bit length isn't greater than 4.
        if bit_length < 4 {
            bail!("Invalid bit length {}", bit_length);
        }

        let mut max = BigNum::new_secure()?;
        max.set_bit(bit_length.into())?;
        max.sub_word(1)?;

        // Starting point
        let mut prime = msecret.extract_big_num(&max)?;

        // Make our starting point odd by making sure the
        // least-significant bit is set.
        prime.set_bit(0)?;

        // Make sure the most-significant two bits are set.
        // This ensures the resulting prime is relatively large.
        prime.set_bit((bit_length - 1).into())?;

        if bit_length > 32 {
            prime.set_bit((bit_length - 2).into())?;
        }

        // Our primality-test loop. Here we simply check to see if the number
        // is prime and, if it isn't, increment by two and try again.
        while !prime.is_prime_fasttest(0, &mut ctx, true)? {
            prime.add_word(2)?;
        }

        Ok(prime)
    }

    fn extract_prime_v1_big_uint(&self, bit_length: u16) -> Result<num_bigint::BigUint> {
        use num_bigint::BigUint;
        use num_bigint_dig::prime::*;
        use num_traits::identities::*;

        const SALT: &[u8] = b"\x00Prime_v1";

        let bit_length: usize = bit_length.into();
        let msecret = self.subsecret_from_salt(SALT)?;

        // The algorithm we are using doesn't really work for small bit sizes,
        // so we fail if the bit length isn't greater than 4.
        if bit_length < 4 {
            bail!("Invalid bit length {}", bit_length);
        }

        let one = BigUint::one();

        let max = (&one << bit_length) - &one;

        // Starting point
        let mut prime = msecret.extract_big_uint(&max)?;

        prime |= &one;

        // Make sure the most-significant two bits are set,
        // except for numbers 32 bits or smaller (where we only set one bit)
        // This ensures the resulting prime is relatively large.
        prime |= &one << (bit_length - 1);
        if bit_length > 32 {
            prime |= &one << (bit_length - 2);
        }

        if probably_prime(&prime, 20) {
            Ok(prime)
        } else {
            Ok(next_prime(&prime))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::prime::probably_prime;
    use num_bigint::BigUint;

    /// Basic verification that the prime derivation algorithm produces
    /// an expected result.
    #[test]
    fn test_prime_smoketest() {
        let prime = Secret::ZERO.extract_prime_v1_big_uint(512).unwrap();

        assert_eq!(hex::encode(prime.to_bytes_be()),"df5fcd4d2f06b8ea31b0a579774925d4356396af9532e50f4defe9449f5922312ed145b1bb8452ad46116aba52d3296407054ee3c5e5d32ed1627063c3a8087d".to_string());

        // This test verifies that specific prime numbers that were known to be problematic
        // for some versions of [`probably_prime`].
        assert!(probably_prime(&BigUint::from(1579751u32), 20));
        assert!(probably_prime(&BigUint::from(1884791u32), 20));
        assert!(probably_prime(&BigUint::from(3818929u32), 20));
        assert!(probably_prime(&BigUint::from(4080359u32), 20));
        assert!(probably_prime(&BigUint::from(4145951u32), 20));
    }

    #[test]
    fn test_prime_shorttest() {
        let mut hash = Sha256::default();

        for m in [32, 128, 256, 512, 1024] {
            for i in 0..100 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let prime = secret.extract_prime_v1_big_uint(m).unwrap().to_bytes_be();
                hash.update(&prime);
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "debb8b2c26b0e8012f3e0a4d42381fc2220e946cecfc17186958c2209c81eeff"
        );
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_prime_shorttest_openssl() {
        let mut hash = Sha256::default();

        for m in [32, 128, 256, 512, 1024] {
            for i in 0..100 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let prime = secret.extract_prime_v1_bignum(m).unwrap().to_vec();
                hash.update(&prime);
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "debb8b2c26b0e8012f3e0a4d42381fc2220e946cecfc17186958c2209c81eeff"
        );
    }

    /// This is a long test that makes sure that the prime number calculations
    /// are correct with a high probability. This test takes a long time,
    /// so it is gated with the `longtest` feature.
    #[cfg(feature = "longtest")]
    #[test]
    fn test_prime_longtest() {
        let mut hash = Sha256::default();

        for m in [32, 128, 256, 512, 1024] {
            for i in 0..5000 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let prime = secret.extract_prime_v1_big_uint(m).unwrap().to_bytes_be();
                hash.update(&prime);
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "f2e74d37971abb63ba2422f9341a2d555aa52cf8403f6c00451725a1404219f8"
        );
    }

    /// This is a long test that makes sure that the prime number calculations
    /// by OpenSSL are correct with a high probability. This test takes a long time,
    /// so it is gated with the `longtest` feature.
    #[cfg(all(feature = "openssl", feature = "longtest"))]
    #[test]
    fn test_prime_longtest_openssl() {
        let mut hash = Sha256::default();

        for m in [32, 128, 256, 512, 1024] {
            for i in 0..5000 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let prime = secret.extract_prime_v1_bignum(m).unwrap().to_vec();
                hash.update(&prime);
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "f2e74d37971abb63ba2422f9341a2d555aa52cf8403f6c00451725a1404219f8"
        );
    }
}
