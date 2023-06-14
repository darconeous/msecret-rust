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

#[derive(Debug, clap::Args)]
pub struct CommandPrime {
    #[arg(value_name = "BIT-LENGTH")]
    bits: u16,

    #[arg(short, long, value_name = "FORMAT", default_value = "base10")]
    format: BinFormat,
}

impl CommandPrime {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();
        let secret = tool_state.current_secret()?;

        let bn = secret.extract_prime_v1_big_uint(self.bits)?;
        self.format.write(out, &bn.to_bytes_be())?;
        Ok(())
    }
}
