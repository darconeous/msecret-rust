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
use rand::rngs::OsRng;
use zeroize::Zeroizing;

#[derive(Debug, clap::Subcommand)]
pub enum CommandRsa {
    /// Generates an RSA key and prints the public portion.
    Public {
        #[arg(short, long, value_name = "BITS", default_value = "2048")]
        mod_bits: u16,

        /// File to store the public key in PEM format.
        #[arg(short = 'o', long = "output", value_name = "FILENAME")]
        output: Option<std::path::PathBuf>,

        #[arg(short, long, default_value = "pem")]
        format: RsaFormat,
    },

    /// Generates an RSA key and prints the private portion.
    Private {
        #[arg(short, long, value_name = "BITS", default_value = "2048")]
        mod_bits: u16,

        /// File to store the private key in PEM format.
        #[arg(short = 'o', long = "output", value_name = "FILENAME")]
        output: Option<std::path::PathBuf>,

        #[arg(short, long, default_value = "pem")]
        format: RsaFormat,

        /// Encrypt the private key with the given password.
        #[arg(long)]
        password: Option<String>,
    },

    /// Encrypts data using the RSA public key.
    #[command(subcommand)]
    Encrypt(RsaPaddingArgs),

    /// Decrypts data using the RSA private key.
    #[command(subcommand)]
    Decrypt(RsaPaddingArgs),

    /// Creates a PKCS#1v1.5 signature using the RSA private key.
    Sign {
        /// If present, the data will contain the pre-hashed digest of the data to be signed.
        /// Do not use this unless you know what you are doing. If not specified, will hash
        /// using SHA256.
        #[arg(long)]
        prehash: bool,

        #[arg(short, long, value_name = "BITS", default_value = "2048")]
        mod_bits: u16,

        #[arg(short, long, value_name = "FORMAT", default_value = "hex")]
        format: BinFormat,

        #[arg(value_name = "DATA")]
        data: String,
    },

    /// Verifies a PKCS#1v1.5 signature using the RSA private key.
    Verify {
        /// If present, the data will contain the pre-hashed digest of the data to be verified.
        /// Do not use this unless you know what you are doing.
        #[arg(long)]
        prehash: bool,

        #[arg(short, long, value_name = "BITS", default_value = "2048")]
        mod_bits: u16,

        #[arg(short, long, value_name = "FORMAT", default_value = "hex")]
        format: BinFormat,

        #[arg(value_name = "DATA")]
        data: String,

        #[arg(value_name = "SIGNATURE")]
        signature: String,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum RsaPaddingArgs {
    /// RSA WITHOUT PADDING. **DO NOT USE UNLESS YOU KNOW WHAT YOU ARE DOING**
    Raw {
        #[arg(short, long, value_name = "BITS", default_value = "2048")]
        mod_bits: u16,

        /// You must specify this flag to acknowledge that you know what you are doing.
        #[arg(long, default_value = "false")]
        i_know_what_i_am_doing: bool,

        #[arg(short, long, value_name = "FORMAT", default_value = "hex")]
        format: BinFormat,

        #[arg(value_name = "DATA")]
        data: String,
    },

    /// OAEP-SHA256 Padding.
    OaepSha256 {
        #[arg(short, long, value_name = "BITS", default_value = "2048")]
        mod_bits: u16,

        #[arg(short, long, value_name = "FORMAT", default_value = "hex")]
        format: BinFormat,

        #[arg(value_name = "DATA")]
        data: String,
    },
}

impl CommandRsa {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();
        let secret = tool_state.current_secret()?;
        match self {
            CommandRsa::Public {
                mod_bits,
                output,
                format,
            } => {
                use ::rsa::pkcs8::EncodePublicKey;
                let rsa = secret.extract_rsa_v1_public(*mod_bits)?;

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive(format!("RSA-{}", mod_bits));

                let ret = match format {
                    RsaFormat::Pem => rsa.to_public_key_pem(Default::default())?.into_bytes(),
                    RsaFormat::Der => rsa.to_public_key_der()?.to_vec(),
                    RsaFormat::Debug => {
                        use ::rsa::traits::PublicKeyParts;
                        let mut ret = vec![];
                        writeln!(ret, "e: {}", rsa.e())?;
                        writeln!(ret, "n: {}", rsa.n())?;
                        ret
                    }
                };

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }
            }
            CommandRsa::Private {
                mod_bits,
                output,
                format,
                password,
            } => {
                use ::rsa::pkcs8::EncodePrivateKey;
                let rsa = secret.extract_rsa_v1_private(*mod_bits)?;

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive(format!("RSA-{}", mod_bits));

                let ret = match format {
                    RsaFormat::Pem => {
                        if let Some(password) = password.as_ref() {
                            Zeroizing::new(
                                rsa.to_pkcs8_encrypted_pem(OsRng, password, Default::default())?
                                    .to_string()
                                    .into_bytes(),
                            )
                        } else if let Ok(password) = std::env::var("PKCS8_PASSWORD") {
                            Zeroizing::new(
                                rsa.to_pkcs8_encrypted_pem(OsRng, password, Default::default())?
                                    .to_string()
                                    .into_bytes(),
                            )
                        } else {
                            Zeroizing::new(
                                rsa.to_pkcs8_pem(Default::default())?
                                    .to_string()
                                    .into_bytes(),
                            )
                        }
                    }
                    RsaFormat::Der => {
                        if let Some(password) = password.as_ref() {
                            rsa.to_pkcs8_encrypted_der(OsRng, password)?.to_bytes()
                        } else if let Ok(password) = std::env::var("PKCS8_PASSWORD") {
                            rsa.to_pkcs8_encrypted_der(OsRng, password)?.to_bytes()
                        } else {
                            rsa.to_pkcs8_der()?.to_bytes()
                        }
                    }
                    RsaFormat::Debug => {
                        use ::rsa::traits::PrivateKeyParts;
                        use ::rsa::traits::PublicKeyParts;
                        let mut ret = Zeroizing::new(vec![]);
                        writeln!(ret, "e: {}", rsa.e())?;
                        writeln!(ret, "n: {}", rsa.n())?;
                        writeln!(ret, "d: {}", rsa.d())?;
                        writeln!(ret, "p: {}", rsa.primes()[0])?;
                        writeln!(ret, "q: {}", rsa.primes()[1])?;
                        ret
                    }
                };

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }
            }

            CommandRsa::Encrypt(RsaPaddingArgs::Raw {
                i_know_what_i_am_doing: false,
                ..
            })
            | CommandRsa::Decrypt(RsaPaddingArgs::Raw {
                i_know_what_i_am_doing: false,
                ..
            }) => {
                bail!("You clearly don't know what you are doing.");
            }
            CommandRsa::Encrypt(RsaPaddingArgs::Raw {
                mod_bits,
                i_know_what_i_am_doing: true,
                format,
                data,
            }) => {
                let plaintext = format.try_from_str(data)?;
                let mut ciphertext = vec![];
                ciphertext.resize_with(((mod_bits + 7) / 8).into(), Default::default);

                let len = secret.encrypt_rsa_v1_raw(*mod_bits, &plaintext, &mut ciphertext)?;

                ciphertext.truncate(len);

                format.write(out, &ciphertext)?;
            }

            CommandRsa::Encrypt(RsaPaddingArgs::OaepSha256 {
                mod_bits,
                format,
                data,
            }) => {
                let plaintext = format.try_from_str(data)?;
                let mut ciphertext = vec![];
                ciphertext.resize_with(((mod_bits + 7) / 8).into(), Default::default);

                let len =
                    secret.encrypt_rsa_v1_oaep_sha256(*mod_bits, &plaintext, &mut ciphertext)?;

                ciphertext.truncate(len);

                format.write(out, &ciphertext)?;
            }

            CommandRsa::Decrypt(RsaPaddingArgs::Raw {
                mod_bits,
                i_know_what_i_am_doing: true,
                format,
                data,
            }) => {
                let ciphertext = format.try_from_str(data)?;
                let mut plaintext = vec![];
                plaintext.resize_with(((mod_bits + 7) / 8).into(), Default::default);

                let len = secret.decrypt_rsa_v1_raw(*mod_bits, &ciphertext, &mut plaintext)?;

                plaintext.truncate(len);

                format.write(out, &plaintext)?;
            }

            CommandRsa::Decrypt(RsaPaddingArgs::OaepSha256 {
                mod_bits,
                format,
                data,
            }) => {
                let ciphertext = format.try_from_str(data)?;
                let mut plaintext = vec![];
                plaintext.resize_with(((mod_bits + 7) / 8).into(), Default::default);

                let len =
                    secret.decrypt_rsa_v1_oaep_sha256(*mod_bits, &ciphertext, &mut plaintext)?;

                plaintext.truncate(len);

                format.write(out, &plaintext)?;
            }

            CommandRsa::Sign {
                prehash: true,
                mod_bits,
                format,
                data,
            } => {
                let data = BinFormat::Hex.try_from_str(data)?;
                let mut output = vec![];
                output.resize_with(((mod_bits + 7) / 8).into(), Default::default);

                let len = secret.sign_rsa_v1_pkcs1_v15_prehash(*mod_bits, &data, &mut output)?;

                output.truncate(len);

                format.write(out, &output)?;
            }

            CommandRsa::Verify {
                prehash: true,
                mod_bits,
                format,
                data,
                signature,
            } => {
                let data = BinFormat::Hex.try_from_str(data)?;
                let signature = format.try_from_str(signature)?;

                secret.verify_rsa_v1_pkcs1_v15_prehash(*mod_bits, &data, &signature)?;

                write!(out, "Ok")?;
            }

            CommandRsa::Verify { prehash: false, .. } | CommandRsa::Sign { prehash: false, .. } => {
                bail!("The `--prehash` flag is currently required.")
            }

            #[allow(unreachable_patterns)]
            _ => {
                bail!("Not yet implemented");
            }
        }
        Ok(())
    }
}
