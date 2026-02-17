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
pub enum CommandSecret {
    /// Creates a new, randomly-generated root secret and resets the path.
    Generate,

    /// Loads the all-zeros secret and resets the path.
    ///
    /// This secret value is for testing and verification purposes only.
    Zero,

    /// Prints out secret identifier for the subsecret at this path.
    Id {
        #[arg(short, long, value_name = "FORMAT", default_value = "base58")]
        format: BinFormat,
    },

    /// Generates a secret derived from the given passphrase.
    /// If a passphrase is not provided in the command line, one will be prompted for.
    ///
    /// When --secret-id is given, the passphrase is verified against the expected
    /// secret ID instead of asking for it twice. Up to three attempts are allowed.
    Passphrase {
        passphrase: Option<String>,

        /// Expected secret ID. When provided, the entered passphrase is verified
        /// against this ID rather than asking for the passphrase a second time.
        #[arg(long, value_name = "SECRET_ID")]
        secret_id: Option<SecretId>,
    },

    /// Prints out the raw value of the subsecret at this keypath in hex.
    Export {
        #[arg(short, long, value_name = "FORMAT", default_value = "hex")]
        format: BinFormat,
    },

    /// Saves the root secret to a file.
    Save {
        #[arg(value_name = "FILENAME")]
        filepath: std::path::PathBuf,

        /// Saves the secret as a hex text file 64 bytes long.
        #[arg(short = 'H', long)]
        hex: bool,
    },

    /// Split the secret into several M-of-N shares.
    #[cfg(feature = "share")]
    Share {
        /// `k`: Minimum number of shares to recover the secret.
        #[arg(value_name = "k")]
        k: u8,

        /// `n`: Total number of shares to generate. Must be larger than `k`.
        #[arg(value_name = "n")]
        n: u8,

        #[arg(short, long, default_value = "base58")]
        format: BinFormat,
    },

    /// Recover several secret shares into a secret.
    /// Leave a blank secret once all secrets have been entered.
    #[cfg(feature = "share")]
    Recover,

    /// Loads a secret from a file. File may be raw (32-byte) or hex (64-byte).
    Load {
        #[arg(value_name = "FILENAME")]
        filepath: std::path::PathBuf,
    },
}

impl CommandSecret {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();
        match self {
            CommandSecret::Generate => {
                tool_state.generate()?;
                write!(out, "Created {}", tool_state.current_secret()?.id())?;
                Ok(())
            }

            CommandSecret::Zero => {
                tool_state.import_root(&Secret::ZERO)?;
                write!(out, "Imported {}", tool_state.current_secret()?.id())?;
                Ok(())
            }

            CommandSecret::Id { format } => {
                format.write(out, &tool_state.current_secret()?.id().into_bytes())?;
                Ok(())
            }

            CommandSecret::Export { format } => {
                format.write(out, &tool_state.current_secret()?.bytes()?)?;
                Ok(())
            }

            CommandSecret::Save { filepath, hex } => {
                if *hex {
                    bail!("Hex not supported");
                }
                tool_state.save(filepath)?;
                Ok(())
            }

            CommandSecret::Load { filepath } => {
                tool_state.load(filepath)?;

                write!(out, "Loaded {}", tool_state.current_secret()?.id())?;
                Ok(())
            }

            CommandSecret::Passphrase {
                passphrase,
                secret_id,
            } => {
                if let Some(passphrase) = passphrase.as_ref() {
                    // Passphrase supplied on the command line.
                    let secret = Secret::from_passphrase(passphrase);
                    if let Some(expected_id) = secret_id {
                        if secret.id() != *expected_id {
                            bail!(
                                "Passphrase produces secret ID {}, expected {}",
                                secret.id(),
                                expected_id
                            );
                        }
                    }
                    tool_state.import_root(&secret)?;
                } else if let Some(expected_id) = secret_id {
                    // Secret ID supplied: verify instead of asking twice.
                    let mut imported = false;
                    for attempt in 0..3usize {
                        let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
                        if passphrase.is_empty() {
                            return Ok(());
                        }
                        let secret = Secret::from_passphrase(&passphrase);
                        if secret.id() == *expected_id {
                            tool_state.import_root(&secret)?;
                            imported = true;
                            break;
                        }
                        eprintln!(
                            "Passphrase produces secret ID {}, expected {}.",
                            secret.id(),
                            expected_id
                        );
                        if attempt == 2 {
                            bail!("Too many incorrect passphrase attempts");
                        }
                    }
                    if !imported {
                        bail!("Too many incorrect passphrase attempts");
                    }
                } else {
                    // No secret ID: ask twice to confirm.
                    let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
                    if passphrase.is_empty() {
                        return Ok(());
                    }
                    let passphrase_check = rpassword::prompt_password("Verify passphrase: ")?;
                    if passphrase != passphrase_check {
                        bail!("Passphrases do not match");
                    }
                    tool_state.import_root(&Secret::from_passphrase(passphrase))?;
                }
                write!(out, "Imported {}", tool_state.current_secret()?.id())?;
                Ok(())
            }

            #[cfg(feature = "share")]
            CommandSecret::Share { k: m, n, format } => {
                let shares = tool_state.export()?.split_shares(*n, *m)?;

                for share in shares {
                    format.write(out, &share)?;
                    writeln!(out)?;
                }

                Ok(())
            }

            #[cfg(feature = "share")]
            CommandSecret::Recover => {
                let mut shares = vec![];

                loop {
                    let prompt_str = if let Ok(secret) = Secret::try_from_shares(&shares) {
                        format!("Press return to use `{}`, or enter share: ", secret.id())
                    } else {
                        "Enter Share: ".to_string()
                    };

                    let share_str = rpassword::prompt_password(&prompt_str)?;
                    if share_str.is_empty() {
                        break;
                    } else {
                        let share = if let Ok(share) =
                            BinFormat::try_from_str_len(share_str, Secret::SHARE_LEN)
                        {
                            share
                        } else {
                            eprintln!("Invalid share");
                            continue;
                        };

                        if let Err(err) = Secret::verify_share(&share) {
                            eprintln!("Invalid share ({})", err);
                            continue;
                        }

                        shares.push(share);
                    }
                }

                tool_state.import_root(&Secret::try_from_shares(&shares)?)?;

                write!(out, "Imported {}", tool_state.current_secret()?.id())?;
                Ok(())
            }
        }
    }
}
