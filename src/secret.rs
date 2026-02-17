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

use rand::{CryptoRng, RngCore};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Default, Clone, Ord, PartialOrd, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(pub(crate) [u8; 32]);

impl Secret {
    pub const ZERO: Secret = Secret([0; 32]);

    /// Generates a secret from a passphrase using the ARGON2 algorithm.
    pub fn from_passphrase<T: AsRef<[u8]>>(passphrase: T) -> Secret {
        let passphrase = passphrase.as_ref();
        let salt = b"MSecret_Passphrase_v1";

        const MSECRET_ARGON2_CONFIG: argon2::Config = argon2::Config {
            ad: &[],
            hash_length: 32,
            lanes: 4,
            mem_cost: 262_144,
            secret: &[],
            thread_mode: argon2::ThreadMode::Sequential,
            time_cost: 3,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        };

        let secret =
            Zeroizing::new(argon2::hash_raw(passphrase, salt, &MSECRET_ARGON2_CONFIG).unwrap());

        Secret::try_from_bytes(&secret).unwrap()
    }

    /// Generates a cryptographically random secret.
    pub fn generate() -> Secret {
        Self::generate_from_rng(&mut rand::rngs::OsRng)
    }

    /// Generates a random secret using the given random number generator.
    pub fn generate_from_rng<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Secret {
        let mut ret = Secret::ZERO;
        rng.fill_bytes(&mut ret.0);
        ret
    }

    /// Initializes a secret from a byte slice that is either in raw or hexidecimal form.
    pub fn try_from_bytes_or_hex<T: AsRef<[u8]>>(data: T) -> Result<Secret> {
        let data = data.as_ref();
        if data.len() == 32 {
            Self::try_from_bytes(data)
        } else if data.len() == 64 {
            Self::try_from_hex(data)
        } else {
            bail!("Key data not a known length")
        }
    }

    /// Initializes a secret from a raw 32-byte slice.
    pub fn try_from_bytes<T: AsRef<[u8]>>(data: T) -> Result<Secret> {
        let data = data.as_ref();
        if data.len() == 32 {
            let mut ret = Self::ZERO;
            ret.0.copy_from_slice(data);
            Ok(ret)
        } else {
            bail!("Key bytes not the correct length (should be 32)")
        }
    }

    /// Initializes a secret from a hexidecimal representation.
    pub fn try_from_hex<T: AsRef<[u8]>>(data: T) -> Result<Secret> {
        if data.as_ref().len() != 64 {
            bail!("Incorrect key string length (should be 64)");
        }
        let mut ret = Self::ZERO;
        hex::decode_to_slice(data, &mut ret.0[0..32])?;
        Ok(ret)
    }

    /// Renders the value of the secret as a hexidecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns the value of the secret as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Secret Sharing Support
///
/// We use a variant of Shamir's secret sharing that is defined over GF(256).
/// Each share is 35 bytes long. The first byte is the share number, which
/// is never zero. The remaining 32 bytes comprise the secret. The next byte
/// is a CRC which is calculated over the secret, and the last byte is a
/// CRC calculated over the individual share. This provides some minimal amount
/// of error checking both per-share and for the overall recovered secret.
#[cfg(feature = "share")]
impl Secret {
    pub const SHARE_CRC: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_BLUETOOTH);
    pub const SHARE_LEN: usize = 35;

    pub fn verify_share<S: AsRef<[u8]>>(share: S) -> Result<()> {
        let share = share.as_ref();
        ensure!(share.len() == Self::SHARE_LEN, "Bad Length");
        ensure!(Self::SHARE_CRC.checksum(share) == 0, "Bad CRC");
        Ok(())
    }

    /// Recovers a secret from `k` of the shares previously split using [`Secret::split_shares()`].
    pub fn try_from_shares<S: AsRef<[u8]>>(shares: &[S]) -> Result<Secret> {
        ensure!(!shares.is_empty(), "No shares given");

        // Check the CRCs for each share.
        for i in 0..shares.len() {
            let share = shares.get(i).unwrap().as_ref();
            if let Err(err) = Self::verify_share(share) {
                bail!("{} for share", err);
            }
        }

        let recovered: Vec<u8> = gf256::shamir::shamir::reconstruct(shares);

        // Check the CRC for the recovered secret.
        ensure!(
            Self::SHARE_CRC.checksum(&recovered[..recovered.len() - 1]) == 0,
            "Bad CRC for recovered secret"
        );

        Secret::try_from_bytes(&recovered[..recovered.len() - 2])
    }

    /// Splits the secret into `n` shares, of which `k` are required to recover the secret.
    pub fn split_shares(&self, n: u8, k: u8) -> Result<Vec<Vec<u8>>> {
        ensure!(k != 0, "`k` cannot be zero.");
        ensure!(n != 0, "`n` cannot be zero.");
        ensure!(k <= n, "`k` cannot be larger than `n`.");

        let mut secret = Zeroizing::new(self.0.to_vec());

        // Add a CRC byte to the end of the secret.
        // This is used as a final sanity check to give some amount of
        // confidence that the recovered secret is correct.
        let crc = Self::SHARE_CRC.checksum(secret.as_slice());
        secret.push(crc);

        // Make sure the CRC verifies.
        assert_eq!(Self::SHARE_CRC.checksum(secret.as_slice()), 0);

        // Split the secret+crc into shares.
        let mut shares: Vec<Vec<u8>> =
            gf256::shamir::shamir::generate(&secret, n as usize, k as usize);

        for share in shares.iter_mut() {
            // Add another CRC byte to each share.
            // These are used to ensure that the individual shares
            // are being entered correctly.
            let crc = Self::SHARE_CRC.checksum(share.as_slice());
            share.push(crc);

            // Make sure the CRC verifies.
            assert_eq!(Self::SHARE_CRC.checksum(share.as_slice()), 0);
        }

        Ok(shares)
    }
}

impl Derivable for Secret {
    fn bytes(&self) -> Result<[u8; 32]> {
        Ok(self.0)
    }

    /// Returns the secret identifier.
    fn id(&self) -> SecretId {
        let Secret(bytes) = self.subsecret_from_salt(b"\x00SecretId").unwrap();
        let mut ret = [0u8; SecretId::LEN];
        ret.copy_from_slice(&bytes.as_slice()[0..SecretId::LEN]);
        ret.into()
    }
}

impl Debug for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({})", hex::encode(self.0))
    }
}

impl FromStr for Secret {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_from_hex(s)
    }
}

impl Display for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[cfg(feature = "share")]
    fn test_secret_sharing() {
        let mut shares = Secret::ZERO.split_shares(5, 3).unwrap();

        // 5 shares should decode fine.
        assert_eq!(Secret::try_from_shares(&shares).unwrap(), Secret::ZERO);

        // 4 shares should decode fine.
        shares.pop();
        assert_eq!(Secret::try_from_shares(&shares).unwrap(), Secret::ZERO);

        // 3 shares should decode fine.
        shares.pop();
        assert_eq!(Secret::try_from_shares(&shares).unwrap(), Secret::ZERO);

        // 2 shares should not be enough.
        shares.pop();
        assert!(Secret::try_from_shares(&shares).is_err());
    }
}
