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

//! # MSecret — Experimental Key Derivation Crate #
//!
//! [GitHub](https://github.com/darconeous/msecret-rust)
//!
//! This is the reference implementation crate for the [MSecret specification][MSECRET]
//! written in Rust. You can use this crate to deterministically derive
//! various types of data (bytes, integers, primes, etc) and cryptographic
//! keys (RSA, ECC, etc) from a 256-bit [`Secret`].
//!
//! [MSECRET]: https://github.com/darconeous/msecret-rust/blob/main/doc/MSECRET.md
//!

#![forbid(unsafe_code)]

extern crate num_bigint_dig as num_bigint;

mod rsa;
pub use crate::rsa::*;

mod ec;
pub use ec::*;

mod bitcoin;
pub use bitcoin::*;

mod password;
pub use password::*;

mod integer;
pub use integer::*;

mod secret;
pub use secret::*;

mod bytes;
pub use bytes::*;

mod prime;
pub use prime::*;

mod tool_state;
pub use tool_state::*;

#[cfg(test)]
mod tests;

#[macro_use]
#[allow(unused_imports)]
pub mod prelude {
    pub use crate::Derivable as _;
    pub use crate::Ecc as _;
    pub use crate::ExtractBitcoinV1 as _;
    pub use crate::ExtractBytes as _;
    pub use crate::ExtractInteger as _;
    pub use crate::ExtractPassword as _;
    pub use crate::ExtractPrimeV1 as _;
    pub use crate::ExtractRsaV1 as _;
    pub use crate::MutateWith as _;
    pub use crate::SubsecretFrom as _;
    pub use crate::ToolState as _;
}

#[doc(hidden)]
#[macro_use]
#[allow(unused_imports)]
pub(crate) mod prelude_internal {
    pub use crate::Derivable;
    pub use crate::Ecc;
    pub use crate::ExtractBitcoinV1;
    pub use crate::ExtractBytes;
    pub use crate::ExtractInteger;
    pub use crate::ExtractPassword;
    pub use crate::ExtractPrimeV1;
    pub use crate::ExtractRsaV1;
    pub use crate::MutateWith;
    pub use crate::Result;
    pub use crate::Secret;
    pub use crate::SecretId;
    pub use crate::SubsecretFrom;
    pub use crate::ToolState;

    pub use ::anyhow::{bail, ensure, format_err, Error};
    pub use ::digest::Digest;
    pub use ::hkdf::Hkdf;
    pub use ::ripemd::Ripemd160;
    pub use ::sha2::Sha256;

    pub use ::std::fmt::Debug;
    pub use ::std::fmt::{Display, Formatter};
    pub use ::std::path::Path;

    pub use hex_literal::hex;
}

use crate::prelude_internal::*;

/// Convenience return type.
pub type Result<T = (), E = Error> = std::result::Result<T, E>;

pub trait Derivable:
    MutateWith
    + SubsecretFrom
    + ExtractBytes
    + ExtractInteger
    + ExtractBitcoinV1
    + Ecc
    + ExtractPassword
    + ExtractPrimeV1
    + ExtractRsaV1
    + Clone
    + Debug
{
    fn bytes(&self) -> Result<[u8; 32]>;

    /// Returns the secret identifier for this secret.
    fn id(&self) -> SecretId;
}

#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SecretId(pub(crate) [u8; SecretId::LEN]);

impl SecretId {
    const LEN: usize = 16;

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; SecretId::LEN] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; SecretId::LEN] {
        self.0
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl Display for SecretId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Kinda wasteful, but bs58 doesn't provide any good way to deal with this case
        // without a double allocation at the moment, so we will just deal with it.
        f.write_str(&self.to_string())
    }
}

impl From<[u8; SecretId::LEN]> for SecretId {
    fn from(value: [u8; SecretId::LEN]) -> Self {
        SecretId(value)
    }
}

pub trait MutateWith {
    fn mutate_with_salt(&mut self, salt: &[u8]) -> Result;

    fn mutate_with_label(&mut self, label: &str) -> Result {
        self.mutate_with_salt(label.as_bytes())
    }

    fn mutate_with_path(&mut self, path: &str) -> Result {
        for label in path.split('/').filter(|w| !w.is_empty()) {
            let (label, count) = if let Some((label, count_str)) = label.split_once('@') {
                if count_str.is_empty() {
                    bail!("Missing count after '@'");
                }
                (label, count_str.parse::<u32>()?)
            } else {
                (label, 1)
            };

            if count == 0 {
                bail!("Zero label count");
            }

            for _ in 0..count {
                self.mutate_with_label(label)?;
            }
        }

        Ok(())
    }
}

impl MutateWith for Secret {
    fn mutate_with_salt(&mut self, salt: &[u8]) -> Result {
        let salt = if salt.is_empty() { None } else { Some(salt) };

        self.0 = Hkdf::<Sha256>::extract(salt, self.as_bytes()).0.into();
        Ok(())
    }
}

pub trait SubsecretFrom: Sized {
    fn subsecret_from_salt(&self, salt: &[u8]) -> Result<Self>;

    fn subsecret_from_label(&self, label: &str) -> Result<Self>;

    fn subsecret_from_path(&self, path: &str) -> Result<Self>;
}

impl SubsecretFrom for Secret {
    fn subsecret_from_salt(&self, salt: &[u8]) -> Result<Secret> {
        let mut ret = self.clone();
        ret.mutate_with_salt(salt)?;
        Ok(ret)
    }

    fn subsecret_from_label(&self, label: &str) -> Result<Secret> {
        let mut ret = self.clone();
        ret.mutate_with_label(label)?;
        Ok(ret)
    }

    fn subsecret_from_path(&self, path: &str) -> Result<Secret> {
        let mut ret = self.clone();
        ret.mutate_with_path(path)?;
        Ok(ret)
    }
}
