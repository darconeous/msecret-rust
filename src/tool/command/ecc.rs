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

#[cfg(feature = "openssl")]
use std::ffi::c_int;

#[cfg(feature = "openssl")]
use ::openssl::{ec::EcGroup, nid::Nid};

use ed25519_dalek::ed25519;
use hex_literal::hex;
use openssl::symm::Cipher;
use rand::rngs::OsRng;

#[derive(Debug, clap::Subcommand, Clone)]
pub enum CommandEcc {
    /// List all of the supported curves.
    List,

    /// Generate the public key for the given curve.
    Public {
        /// The name of the curve to use.
        curve: String,

        #[arg(short = 'o', long = "output", value_name = "FILENAME")]
        output: Option<std::path::PathBuf>,

        #[arg(short, long)]
        format: Option<EccFormat>,
    },

    /// Generate the private key for the given curve.
    Private {
        /// The name of the curve to use.
        curve: String,

        #[arg(short = 'o', long = "output", value_name = "FILENAME")]
        output: Option<std::path::PathBuf>,

        #[arg(short, long)]
        format: Option<EccFormat>,

        /// Encrypt the private key with the given password.
        #[arg(long)]
        password: Option<String>,
    },

    /// Sign the given data using ECDSA/EdDSA.
    Sign {
        curve: String,

        /// If present, data is pre-hashed digest. If you don't understand, don't use this.
        /// If not specified, will hash using SHA256.
        #[arg(long)]
        prehash: bool,

        /// Input format for DATA. Defaults to hex. Cannot be used with --file.
        #[arg(short, long, value_name = "FORMAT")]
        in_format: Option<BinFormat>,

        /// The data to sign, or (if prehash is set) the hash to sign.
        /// Mutually exclusive with --file.
        #[arg(value_name = "DATA", required_unless_present = "file", conflicts_with = "file")]
        data: Option<String>,

        /// Read input data as raw bytes from a file. Mutually exclusive with DATA and --in-format.
        #[arg(long, value_name = "FILE", conflicts_with = "data")]
        file: Option<std::path::PathBuf>,

        #[arg(short = 'f', long, value_name = "FORMAT", default_value = "hex")]
        out_format: BinFormat,

        /// Write signature to this file instead of stdout. Respects --out-format.
        #[arg(short = 'o', long = "sig-file", value_name = "FILE")]
        sig_file: Option<std::path::PathBuf>,
    },

    /// Verify that a given signature matches the given data using ECDSA/EdDSA.
    Verify {
        curve: String,

        /// If present, data is pre-hashed digest. If you don't understand, don't use this.
        /// If not specified, will hash using SHA256.
        #[arg(long)]
        prehash: bool,

        /// Hex-encoded signature. Mutually exclusive with --sig-file.
        #[arg(value_name = "SIGNATURE-HEX", required_unless_present = "sig_file", conflicts_with = "sig_file")]
        signature: Option<String>,

        /// Read signature (hex-encoded) from this file. Mutually exclusive with SIGNATURE-HEX.
        #[arg(long = "sig-file", value_name = "FILE", conflicts_with = "signature")]
        sig_file: Option<std::path::PathBuf>,

        /// The data to verify, or (if prehash is set) the hash to verify.
        /// Mutually exclusive with --file.
        #[arg(value_name = "DATA", required_unless_present = "file", conflicts_with = "file")]
        data: Option<String>,

        /// Read input data as raw bytes from a file. Mutually exclusive with DATA.
        #[arg(long, value_name = "FILE", conflicts_with = "data")]
        file: Option<std::path::PathBuf>,
    },
}

/// Creates an EcGroup from a string description.
#[cfg(feature = "openssl")]
fn ec_group_from_str<T: AsRef<str>>(curve: T) -> Result<EcGroup, Error> {
    let mut curve = curve.as_ref();
    if curve == "p256" || curve == "p-256" || curve == "nistp256" || curve == "secp256r1" {
        // Allow the "p256" shorthand.
        curve = "prime256v1";
    }
    if curve == "p384" || curve == "p-384" || curve == "nistp384" {
        // Allow the "p384" shorthand.
        curve = "secp384r1";
    }
    if curve == "p521" || curve == "p-521" || curve == "nistp521" {
        // Allow the "p521" shorthand.
        curve = "secp521r1";
    }
    if let Ok(nid) = curve.parse::<c_int>() {
        Ok(EcGroup::from_curve_name(Nid::from_raw(nid))?)
    } else {
        /* Here we are just annoyingly looping through every single
         * NID value to find a match because we don't have safe access
         * to the right call from OpenSSL.
         */
        for i in 0..32000 {
            let nid = Nid::from_raw(i);
            if let Ok(group) = EcGroup::from_curve_name(nid) {
                if nid.short_name().unwrap() == curve {
                    return Ok(group);
                }
            }
        }
        bail!("Unknown ECC curve {:?}", curve);
    }
}

/// Makes a public SSH key from a `ed25519_dalek::VerifyingKey`.
fn ed25519_public_to_openssh(key: &ed25519_dalek::VerifyingKey) -> Result<String, Error> {
    let mut vec = hex!("0000000b7373682d6564323535313900000020").to_vec();
    vec.extend_from_slice(key.as_bytes().as_slice());
    Ok(format!(
        "ssh-ed25519 {}",
        BinFormat::Base64.to_string(&vec)?
    ))
}

/// Makes a private OpenSSH key from a `ed25519_dalek::SigningKey`.
fn ed25519_private_to_openssh(private_key: &ed25519_dalek::SigningKey) -> Result<String, Error> {
    let public_key: ed25519_dalek::VerifyingKey = private_key.into();
    let pub64 = public_key.as_bytes().as_slice();
    let priv64 = private_key.to_bytes();
    let part1 = hex!("6f70656e7373682d6b65792d763100000000046e6f6e65000000046e6f6e650000000000000001000000330000000b7373682d6564323535313900000020");
    let part2 = hex!("0000008800000000000000000000000b7373682d6564323535313900000020");
    let part3 = b"\x00\x00\x00@";
    let part4 = hex!("000000000102030405");
    let mut vec = part1.to_vec();
    vec.extend_from_slice(pub64);
    vec.extend_from_slice(part2.as_slice());
    vec.extend_from_slice(pub64);
    vec.extend_from_slice(part3.as_slice());
    vec.extend_from_slice(&priv64);
    vec.extend_from_slice(pub64);
    vec.extend_from_slice(part4.as_slice());
    Ok(format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        BinFormat::Base64.to_string(&vec)?
    ))
}

/// Resolve the signature bytes for verify from either a hex string arg or a --sig-file (hex).
fn resolve_sig(
    signature: &Option<String>,
    sig_file: &Option<std::path::PathBuf>,
) -> Result<Vec<u8>, Error> {
    if let Some(path) = sig_file {
        let hex_str = std::fs::read_to_string(path)?;
        BinFormat::Hex.try_from_str(hex_str.trim())
    } else {
        BinFormat::Hex.try_from_str(signature.as_deref().unwrap())
    }
}

/// Resolve the bytes to sign/verify from either a DATA string (decoded with `in_format`,
/// defaulting to hex) or a `--file` path (read as raw bytes). Errors if both `--file` and
/// `--in-format` are specified.
fn resolve_sign_data(
    data: &Option<String>,
    file: &Option<std::path::PathBuf>,
    in_format: Option<BinFormat>,
) -> Result<Vec<u8>, Error> {
    if let Some(path) = file {
        if in_format.is_some() {
            bail!("--in-format cannot be used together with --file");
        }
        Ok(std::fs::read(path)?)
    } else {
        in_format
            .unwrap_or(BinFormat::Hex)
            .try_from_str(data.as_deref().unwrap())
    }
}

impl CommandEcc {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let tool_state = tool_state.as_mut();

        // Catch likely missing curve name: if the "curve" positional looks like hex data
        // or a signature rather than a real curve name, nudge the user.
        match self {
            CommandEcc::Sign { curve, .. } | CommandEcc::Verify { curve, .. }
                if curve.len() > 40 =>
            {
                let subcmd = if matches!(self, CommandEcc::Sign { .. }) {
                    "sign"
                } else {
                    "verify"
                };
                bail!(
                    "Unknown curve {:?}. Did you forget to specify the curve name?\n\
                     Usage: ecc {subcmd} <CURVE> ...",
                    if curve.len() > 20 {
                        format!("{}...", &curve[..20])
                    } else {
                        curve.clone()
                    }
                );
            }
            _ => {}
        }

        match self {
            CommandEcc::List => {
                writeln!(out, "ed25519")?;
                writeln!(out, "x25519")?;

                /* Here we are just stup1dly looping through every single
                 * NID value and seeing if we can successfully use
                 * EC_KEY_new_by_curve_name() on it. If we can, we get the
                 * short name and print it out. Kinda stup1d, but a lot
                 * shorter than a "real" version.
                 */
                #[cfg(feature = "openssl")]
                for i in 0..32000 {
                    let nid = Nid::from_raw(i);
                    if let Ok(_group) = EcGroup::from_curve_name(nid) {
                        writeln!(out, "{}", nid.short_name().unwrap())?;
                    }
                }
                Ok(())
            }
            CommandEcc::Public {
                curve,
                output,
                format,
            } if curve == "ed25519" => {
                let secret = tool_state.current_secret()?;
                let key = secret.extract_ed25519_public()?;

                let ret = match format.unwrap_or(EccFormat::Pkcs8) {
                    EccFormat::BinFormat(format) => format.to_bytes(key.as_bytes())?,
                    EccFormat::Ssh => {
                        let ssh_key = ed25519_public_to_openssh(&key)?;
                        format!("{} msecret-{}", ssh_key, secret.id())
                            .as_bytes()
                            .to_vec()
                    }
                    EccFormat::Pkcs8 => {
                        use ed25519::pkcs8::EncodePublicKey;
                        key.to_public_key_pem(Default::default())?
                            .as_bytes()
                            .to_vec()
                    }
                };

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive("ed25519");

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }

                Ok(())
            }

            CommandEcc::Private {
                curve,
                output,
                format,
                password,
            } if curve == "ed25519" => {
                let secret = tool_state.current_secret()?;
                let key = secret.extract_ed25519_private()?;

                let ret = match format.unwrap_or(EccFormat::Pkcs8) {
                    EccFormat::BinFormat(format) => format.to_bytes(&key.to_bytes())?,
                    EccFormat::Ssh => ed25519_private_to_openssh(&key)?.as_bytes().to_vec(),
                    EccFormat::Pkcs8 => {
                        use ed25519_dalek::pkcs8::EncodePrivateKey;
                        if let Some(password) = password.as_ref() {
                            key.to_pkcs8_encrypted_pem(OsRng, password, Default::default())?
                                .as_bytes()
                                .to_vec()
                        } else if let Ok(password) = std::env::var("PKCS8_PASSWORD") {
                            key.to_pkcs8_encrypted_pem(OsRng, password, Default::default())?
                                .as_bytes()
                                .to_vec()
                        } else {
                            key.to_pkcs8_pem(Default::default())?.as_bytes().to_vec()
                        }
                    }
                };

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive("ed25519");

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }

                Ok(())
            }

            CommandEcc::Public {
                curve,
                output,
                format,
            } if curve == "x25519" => {
                let secret = tool_state.current_secret()?;
                let key = secret.extract_x25519_public()?;

                let ret = match format.unwrap_or(EccFormat::BinFormat(BinFormat::Hex)) {
                    EccFormat::BinFormat(format) => format.to_bytes(&key)?,
                    _ => bail!("Unsupported format"),
                };

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive("x25519");

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }

                Ok(())
            }

            CommandEcc::Private {
                curve,
                output,
                format,
                password: None,
            } if curve == "x25519" => {
                let secret = tool_state.current_secret()?;
                let key = secret.extract_x25519_private()?;

                let ret = match format.unwrap_or(EccFormat::BinFormat(BinFormat::Hex)) {
                    EccFormat::BinFormat(format) => format.to_bytes(&key)?,
                    _ => bail!("Unsupported format"),
                };

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive("x25519");

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }

                Ok(())
            }

            #[cfg(feature = "openssl")]
            CommandEcc::Public {
                curve,
                output,
                format,
            } => {
                let secret = tool_state.current_secret()?;
                let group = ec_group_from_str(curve)?;
                let eckey = secret.extract_ec_v1_public_openssl(&group)?;

                let mut ctx = openssl::bn::BigNumContext::new()?;

                let ret = match format.unwrap_or(EccFormat::Pkcs8) {
                    EccFormat::BinFormat(format) => {
                        format.to_bytes(&eckey.public_key().to_bytes(
                            &group,
                            openssl::ec::PointConversionForm::COMPRESSED,
                            &mut ctx,
                        )?)?
                    }
                    EccFormat::Ssh => bail!("SSH not supported for this curve"),
                    EccFormat::Pkcs8 => eckey.public_key_to_pem()?,
                };

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive(curve);

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }

                Ok(())
            }

            #[cfg(feature = "openssl")]
            CommandEcc::Private {
                curve,
                output,
                format,
                password,
            } => {
                let secret = tool_state.current_secret()?;
                let group = ec_group_from_str(curve)?;
                let eckey = secret.extract_ec_v1_private_openssl(&group)?;

                let ret = match format.unwrap_or(EccFormat::Pkcs8) {
                    EccFormat::BinFormat(format) => {
                        format.to_bytes(&eckey.private_key().to_vec_padded(32)?)?
                    }
                    EccFormat::Ssh => bail!("SSH not supported for this curve"),
                    EccFormat::Pkcs8 => {
                        if let Some(password) = password.as_ref() {
                            eckey.private_key_to_pem_passphrase(
                                Cipher::aes_256_cbc(),
                                password.as_bytes(),
                            )?
                        } else if let Ok(password) = std::env::var("PKCS8_PASSWORD") {
                            eckey.private_key_to_pem_passphrase(
                                Cipher::aes_256_cbc(),
                                password.as_bytes(),
                            )?
                        } else {
                            eckey.private_key_to_pem()?
                        }
                    }
                };

                let keypath = tool_state.get_keypath()?;
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive(curve);

                if let Some(path) = output {
                    std::fs::write(path, &ret)?;
                } else {
                    out.write_all(&ret)?;
                }
                Ok(())
            }

            CommandEcc::Sign {
                curve,
                prehash: false,
                in_format,
                out_format: format,
                data,
                file,
                sig_file,
            } if curve == "ed25519" => {
                let secret = tool_state.current_secret()?;
                let data = resolve_sign_data(data, file, *in_format)?;
                let output = secret.sign_ed25519(&data)?;
                if let Some(path) = sig_file {
                    let mut f = std::fs::File::create(path)?;
                    format.write(&mut f, &output)?;
                } else {
                    format.write(out, &output)?;
                }
                Ok(())
            }

            CommandEcc::Verify {
                curve,
                prehash: false,
                data,
                file,
                signature,
                sig_file,
            } if curve == "ed25519" => {
                let secret = tool_state.current_secret()?;
                let data = resolve_sign_data(data, file, None)?;
                let signature = resolve_sig(signature, sig_file)?;
                secret.verify_ed25519(&data, &signature)?;
                write!(out, "Ok")?;
                Ok(())
            }

            CommandEcc::Sign {
                curve,
                prehash: true,
                in_format,
                out_format: format,
                data,
                file,
                sig_file,
            } if curve == "ed25519" => {
                let secret = tool_state.current_secret()?;
                let data = resolve_sign_data(data, file, *in_format)?;
                let output = secret.sign_ed25519ph(&data, None)?;
                if let Some(path) = sig_file {
                    let mut f = std::fs::File::create(path)?;
                    format.write(&mut f, &output)?;
                } else {
                    format.write(out, &output)?;
                }
                Ok(())
            }

            CommandEcc::Verify {
                curve,
                prehash: true,
                data,
                file,
                signature,
                sig_file,
            } if curve == "ed25519" => {
                let secret = tool_state.current_secret()?;
                let data = resolve_sign_data(data, file, None)?;
                let signature = resolve_sig(signature, sig_file)?;
                secret.verify_ed25519ph(&data, None, &signature)?;
                write!(out, "Ok")?;
                Ok(())
            }

            #[cfg(feature = "openssl")]
            CommandEcc::Sign {
                curve,
                prehash: true,
                in_format,
                out_format,
                data,
                file,
                sig_file,
            } => {
                use openssl::ecdsa::EcdsaSig;
                let secret = tool_state.current_secret()?;
                let group = ec_group_from_str(curve)?;
                let eckey = secret.extract_ec_v1_private_openssl(&group)?;
                let data = resolve_sign_data(data, file, *in_format)?;
                let sig = EcdsaSig::sign(&data, &eckey)?;
                if let Some(path) = sig_file {
                    let mut f = std::fs::File::create(path)?;
                    out_format.write(&mut f, &sig.to_der()?)?;
                } else {
                    out_format.write(out, &sig.to_der()?)?;
                }
                Ok(())
            }

            #[cfg(feature = "openssl")]
            CommandEcc::Verify {
                curve,
                prehash: true,
                data,
                file,
                signature,
                sig_file,
            } => {
                use openssl::ecdsa::EcdsaSig;
                let secret = tool_state.current_secret()?;
                let group = ec_group_from_str(curve)?;
                let eckey = secret.extract_ec_v1_private_openssl(&group)?;
                let data = resolve_sign_data(data, file, None)?;
                let sig = resolve_sig(signature, sig_file)?;
                let verified = EcdsaSig::from_der(&sig)?.verify(&data, &eckey)?;
                ensure!(verified, "Signature doesn't match");
                println!("Ok");
                Ok(())
            }
            #[allow(unreachable_patterns)]
            _ => {
                bail!("Not currently supported");
            }
        }
    }
}
