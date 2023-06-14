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

use anyhow::{bail, format_err, Error};
use base64::Engine;
use clap::builder::PossibleValue;
use msecret::Result;
use std::fmt::{Display, Formatter};
use std::io::{stdout, Write};
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum EccFormat {
    BinFormat(BinFormat),
    Ssh,
    Pkcs8,
}

impl clap::ValueEnum for EccFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            EccFormat::BinFormat(BinFormat::Hex),
            EccFormat::BinFormat(BinFormat::Base64),
            EccFormat::BinFormat(BinFormat::Base58),
            EccFormat::BinFormat(BinFormat::Mnemonic),
            EccFormat::BinFormat(BinFormat::Raw),
            // Note: Skipping over DEC here because it doesn't make a lot of sense.
            EccFormat::Ssh,
            EccFormat::Pkcs8,
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self {
            EccFormat::BinFormat(x) => x.to_possible_value(),
            EccFormat::Ssh => Some(PossibleValue::new("ssh").help("SSH key format")),
            EccFormat::Pkcs8 => {
                Some(PossibleValue::new("pkcs8").help("Standardized key export format"))
            }
        }
    }
}

#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, clap::ValueEnum)]
pub enum RsaFormat {
    /// Standard text PEM format.
    #[default]
    Pem,

    /// Standard binary DER format. (May corrupt terminal)
    Der,

    /// Verbose breakdown of individual components.
    Debug,
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, clap::ValueEnum)]
pub enum BinFormat {
    /// Raw binary value (May corrupt terminal)
    Raw,

    /// Hexidecimal (Base16)
    #[value(alias("b16"))]
    Hex,

    /// Decimal (Base10)
    #[value(alias("b10"), alias("base10"))]
    Dec,

    /// Common Base64 Encoding Scheme
    #[value(alias("b64"))]
    Base64,

    /// Bitcoin's base58 encoding
    #[value(alias("b58"))]
    Base58,

    /// Mnemonic English encoding
    #[value(name = "words", alias("mnemonic"))]
    Mnemonic,
}

impl Display for BinFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BinFormat::Hex => "hex",
            BinFormat::Dec => "dec",
            BinFormat::Raw => "raw",
            BinFormat::Base64 => "base64",
            BinFormat::Base58 => "base58",
            BinFormat::Mnemonic => "mnemonic",
        })
    }
}

impl FromStr for BinFormat {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "hex" | "b16" | "base16" => Ok(BinFormat::Hex),
            "raw" => Ok(BinFormat::Raw),
            "base64" | "b64" => Ok(BinFormat::Base64),
            "base58" | "b58" | "bs58" => Ok(BinFormat::Base58),
            "dec" | "b10" | "base10" => Ok(BinFormat::Dec),
            "words" | "mnemonic" | "mnemonic-en" => Ok(BinFormat::Mnemonic),
            _ => Err(format_err!("Unknown binary format {:?}", s)),
        }
    }
}

impl BinFormat {
    /// Makes a best effort to decode the given string into a vector of the given length.
    pub fn try_from_str_len<T: AsRef<str>>(encoded: T, len: usize) -> Result<Vec<u8>, Error> {
        let encoded = encoded.as_ref();
        let mut ret = vec![];

        if mnemonic::decode(encoded, &mut ret).is_ok() && ret.len() == len {
            return Ok(ret);
        }

        if let Ok(ret) = bs58::decode(encoded).into_vec() {
            if ret.len() == len {
                return Ok(ret);
            }
        }

        if let Ok(ret) = hex::decode(encoded) {
            if ret.len() == len {
                return Ok(ret);
            }
        }

        if let Ok(ret) = base64::engine::general_purpose::STANDARD.decode(encoded) {
            if ret.len() == len {
                return Ok(ret);
            }
        }

        bail!("Unable to decode");
    }

    pub fn write<W: Write>(&self, out: &mut W, bytes: &[u8]) -> Result {
        match self {
            BinFormat::Raw => out.write_all(bytes)?,
            _ => write!(out, "{}", self.to_string(bytes)?)?,
        }
        Ok(())
    }

    pub fn print_out(&self, bytes: &[u8]) -> Result<(), Error> {
        use std::io::IsTerminal;
        match self {
            BinFormat::Raw if stdout().is_terminal() => {
                bail!("Refusing to write raw data to terminal")
            }
            _ => self.write(&mut stdout(), bytes)?,
        }
        Ok(())
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_string(&self, bytes: &[u8]) -> Result<String, Error> {
        Ok(match self {
            BinFormat::Hex => hex::encode(bytes),
            BinFormat::Raw => bail!("Cannot write raw data to a string."),
            BinFormat::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
            BinFormat::Base58 => bs58::encode(bytes).into_string(),
            BinFormat::Dec => num_bigint::BigUint::from_bytes_be(bytes).to_string(),
            BinFormat::Mnemonic => mnemonic::to_string(bytes),
        })
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(match self {
            BinFormat::Raw => bytes.to_vec(),
            _ => self.to_string(bytes)?.into_bytes(),
        })
    }

    /// Tries to decode the given string to a vector using the given format.
    pub fn try_from_str<T: AsRef<str>>(&self, encoded: T) -> Result<Vec<u8>, Error> {
        let encoded = encoded.as_ref();
        Ok(match self {
            BinFormat::Hex => hex::decode(encoded)?,
            BinFormat::Raw => encoded.bytes().collect(),
            BinFormat::Base64 => base64::engine::general_purpose::STANDARD.decode(encoded)?,
            BinFormat::Base58 => bs58::decode(encoded).into_vec()?,
            BinFormat::Dec => num_bigint::BigUint::from_str(encoded)?.to_bytes_be(),
            BinFormat::Mnemonic => {
                let mut ret = vec![];
                mnemonic::decode(encoded, &mut ret)?;
                ret
            }
        })
    }
}
