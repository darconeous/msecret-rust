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
pub struct CommandLs {
    //keypath: Option<String>,
}

impl CommandLs {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();
        let keypath = tool_state.get_keypath()?;
        let key_map = tool_state.key_map_mut();

        if let Some(key_map) = key_map.get_key_map(keypath) {
            for child in key_map.get_children() {
                write!(out, "{} \t[", child)?;

                for primitive in key_map.get_child(child).unwrap().get_primitives() {
                    write!(out, " {}", primitive)?;
                }

                writeln!(out, " ]")?;
            }
        }

        Ok(())
    }
}
