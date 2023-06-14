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

mod btc;
mod bytes;
mod ecc;
mod int;
mod ls_cd;
mod password;
mod prime;
mod rsa;
mod secret;
mod test_vectors;

use crate::bin_format::*;

#[allow(unused_imports)]
use anyhow::{bail, ensure, Error};
use clap::Subcommand;
use msecret::*;
use num_bigint::BigUint;
use std::io::Write;

pub use self::rsa::*;
pub use btc::*;
pub use bytes::*;
pub use ecc::*;
pub use int::*;
pub use ls_cd::*;
pub use password::*;
pub use prime::*;
pub use secret::*;
pub use test_vectors::*;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Lists previously used keypaths relative to the current keypath.
    #[command(alias("list"))]
    Ls(CommandLs),

    /// Changes the current keypath.
    Cd { keypath: String },

    /// Commands related to secret management
    #[command(subcommand)]
    Secret(CommandSecret),

    /// Derives a variable number of bytes from the current secret and keypath.
    Bytes(CommandBytes),

    /// Derives an integer of a specific maximum size from the current secret and keypath.
    #[command(alias("integer"))]
    Int(CommandInt),

    /// Derives a prime of a specific maximum size from the current secret and keypath.
    Prime(CommandPrime),

    /// RSA commands for generating public/private key pairs and performing encryption and decryption.
    #[command(subcommand)]
    Rsa(CommandRsa),

    /// ECC commands for generating public/private key pairs and performing encryption and decryption.
    #[command(alias("ec"), subcommand)]
    Ecc(CommandEcc),

    /// Commands for generating bitcoin addresses and their associated private keys.
    #[command(subcommand)]
    Btc(CommandBtc),

    /// Commands for generating high-quality passwords.
    #[command(subcommand)]
    Password(CommandPassword),

    /// Generate a test-vector document that can be used for verifying implementation correctness.
    TestVectors(CommandTestVectors),

    /// Exits interactive mode.
    #[command(alias("q"), alias("quit"))]
    Exit,
}

impl Command {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        match self {
            Command::Ls(x) => return x.process(tool_state, out),
            Command::Cd { keypath } => {
                let tool_state = tool_state.as_mut();

                tool_state.update_keypath(keypath)?;

                let keypath = tool_state.get_keypath()?;
                let key_map = tool_state.key_map_mut();

                key_map.update(keypath);
            }
            Command::Secret(x) => return x.process(tool_state, out),
            Command::Bytes(x) => return x.process(tool_state, out),
            Command::Int(x) => return x.process(tool_state, out),
            Command::Prime(x) => return x.process(tool_state, out),
            Command::Rsa(x) => return x.process(tool_state, out),
            Command::Ecc(x) => return x.process(tool_state, out),
            Command::Btc(x) => return x.process(tool_state, out),
            Command::Password(x) => return x.process(tool_state, out),
            Command::TestVectors(x) => return x.process(tool_state, out),
            Command::Exit => {}
        }
        Ok(())
    }
}
