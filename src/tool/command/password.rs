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
pub enum CommandPassword {
    /// Generates a very strong, easy-to-read password.
    V1,

    /// Generates a medium-strength password that is optimized for being typed on phone keyboards.
    V2,
}

impl CommandPassword {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();
        let secret = tool_state.current_secret()?;
        match self {
            CommandPassword::V1 => {
                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive("password-v1");

                write!(out, "{}", secret.extract_password_v1()?)?;
            }
            CommandPassword::V2 => {
                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive("password-v2");

                write!(out, "{}", secret.extract_password_v2()?)?;
            }
        }
        Ok(())
    }
}
