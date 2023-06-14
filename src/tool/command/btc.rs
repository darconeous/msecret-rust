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

use super::*;

#[derive(Debug, clap::Subcommand)]
pub enum CommandBtc {
    Addr,
    Wif,
    Private,
    Public,
}

impl CommandBtc {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();
        let secret = tool_state.current_secret()?;
        match self {
            CommandBtc::Addr => write!(out, "{}", secret.extract_bitcoin_v1_address_b58()?)?,
            CommandBtc::Wif => write!(out, "{}", secret.extract_bitcoin_v1_wif_b58()?)?,
            CommandBtc::Private => write!(
                out,
                "{}",
                hex::encode(secret.extract_bitcoin_v1_private_key()?)
            )?,
            CommandBtc::Public => write!(
                out,
                "{}",
                hex::encode(secret.extract_bitcoin_v1_public_key()?)
            )?,
        }
        Ok(())
    }
}
