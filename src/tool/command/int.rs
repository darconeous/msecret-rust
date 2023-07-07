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
pub struct CommandInt {
    #[arg(value_name = "MAX-VALUE")]
    max: String,

    /// Use the interval `[1,max]` instead of `[0,max]`.
    #[arg(long)]
    skip_zero: bool,

    /// Format of the maximum value.
    #[arg(short = 'i', long, value_name = "FORMAT")]
    in_format: Option<BinFormat>,

    /// Format of the output value.
    #[arg(short = 'f', long, value_name = "FORMAT")]
    out_format: Option<BinFormat>,
}

impl CommandInt {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();
        let secret = tool_state.current_secret()?;
        let in_format = if let Some(in_format) = self.in_format {
            in_format
        } else if let Some(out_format) = self.out_format {
            out_format
        } else {
            BinFormat::Dec
        };
        let out_format = self.out_format.unwrap_or(in_format);

        let bytes = if self.skip_zero {
            use num_traits::Zero;
            let max = in_format.try_from_str(&self.max)?;
            let max = BigUint::from_bytes_be(&max);

            ensure!(
                !max.is_zero(),
                "Max value can't be zero when used with `--skip_zero`."
            );

            let one = BigUint::from(1u64);
            let out: BigUint = secret.extract_big_uint(&(max - &one))? + &one;
            out.to_bytes_be()
        } else {
            let max = in_format.try_from_str(&self.max)?;
            secret.extract_int_to_be_vec(&max)?
        };

        let keypath = tool_state.get_keypath()?;

        tool_state
            .key_map_mut()
            .update(keypath)
            .unwrap()
            .add_primitive("integer");

        out_format.write(out, &bytes)?;
        Ok(())
    }
}
