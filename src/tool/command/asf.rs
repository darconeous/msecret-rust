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

use std::process::Command;
use zeroize::Zeroize;

/// Access control type for keychain items.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum AsfAccessType {
    /// No special access control (default keychain protection).
    None,
    /// Require biometric authentication (Touch ID) for key usage.
    Bio,
}

impl std::fmt::Display for AsfAccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsfAccessType::None => write!(f, "none"),
            AsfAccessType::Bio => write!(f, "bio"),
        }
    }
}

#[derive(Debug, clap::Subcommand, Clone)]
pub enum CommandAsfImport {
    /// Import a derived ECC key into the macOS Keychain.
    Ecc {
        /// The ECC curve to use. Currently only prime256v1 (P-256) is supported.
        curve: String,

        /// Label for the keychain item. Defaults to "<SECRET_ID>:<KEYPATH>"
        /// (e.g., "DCUUx9UhnhJErcndchjMsZ:/special/key/path/1").
        #[arg(short = 'l', long = "label")]
        label: Option<String>,

        /// Access control type: "none" (default) or "bio" (Touch ID).
        #[arg(short = 't', long = "access-type", default_value = "none")]
        access_type: AsfAccessType,

        /// Print what would be done without actually importing.
        #[arg(long)]
        dry_run: bool,
    },
}

/// Normalize common P-256 curve name aliases to the canonical name.
fn normalize_asf_curve_name(curve: &str) -> Result<&'static str, Error> {
    match curve {
        "p256" | "p-256" | "nistp256" | "secp256r1" | "prime256v1" => Ok("prime256v1"),
        _ => bail!(
            "Unknown or unsupported curve {:?} for ASF import. \
             Currently only prime256v1 (P-256) is supported.",
            curve
        ),
    }
}

/// Securely write data to a temp file, run a closure, then securely clean up.
/// The file is created with mode 0600 and overwritten with zeros before deletion.
fn with_secure_temp_file<F, R>(
    name: &str,
    data: &[u8],
    f: F,
) -> Result<R, Error>
where
    F: FnOnce(&std::path::Path) -> Result<R, Error>,
{
    let tmp_path = std::env::temp_dir().join(format!("msecret-{}-{}", std::process::id(), name));

    // Write with restricted permissions
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| anyhow::anyhow!("Failed to create temp file: {}", e))?;
        std::io::Write::write_all(&mut file, data)
            .map_err(|e| anyhow::anyhow!("Failed to write temp file: {}", e))?;
    }

    let result = f(&tmp_path);

    // Secure cleanup: overwrite with zeros, then delete
    {
        if let Ok(metadata) = std::fs::metadata(&tmp_path) {
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&tmp_path) {
                let zeros = vec![0u8; metadata.len() as usize];
                let _ = std::io::Write::write_all(&mut file, &zeros);
            }
        }
        let _ = std::fs::remove_file(&tmp_path);
    }

    result
}

/// Build an encrypted PKCS12 file from a P-256 private key using the `openssl`
/// crate (in-memory, key never written to disk unencrypted), then import it
/// into the macOS Keychain via `sc_auth import-ctk-identities`.
fn sc_auth_import(
    secret_key: &p256::SecretKey,
    label: &str,
    access_type: &AsfAccessType,
) -> Result<(), Error> {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};

    // Generate a cryptographically secure random password for the PKCS12 file
    let mut pass_bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut pass_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate random password: {}", e))?;
    let mut p12_pass = hex::encode(pass_bytes);
    pass_bytes.zeroize();

    // Convert p256::SecretKey to openssl EcKey
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| anyhow::anyhow!("Failed to create EC group: {}", e))?;
    let private_bn = BigNum::from_slice(secret_key.to_bytes().as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to create BigNum: {}", e))?;
    let ctx = BigNumContext::new()
        .map_err(|e| anyhow::anyhow!("Failed to create BigNum context: {}", e))?;
    let mut public_point = EcPoint::new(&group)
        .map_err(|e| anyhow::anyhow!("Failed to create EC point: {}", e))?;
    public_point
        .mul_generator(&group, &private_bn, &ctx)
        .map_err(|e| anyhow::anyhow!("Failed to compute public key: {}", e))?;
    let ec_key = EcKey::from_private_components(&group, &private_bn, &public_point)
        .map_err(|e| anyhow::anyhow!("Failed to create EC key: {}", e))?;
    ec_key
        .check_key()
        .map_err(|e| anyhow::anyhow!("EC key validation failed: {}", e))?;
    let pkey = PKey::from_ec_key(ec_key)
        .map_err(|e| anyhow::anyhow!("Failed to create PKey: {}", e))?;

    // Build a self-signed X509 certificate
    let mut name_builder = X509NameBuilder::new()
        .map_err(|e| anyhow::anyhow!("Failed to create X509 name builder: {}", e))?;
    name_builder
        .append_entry_by_text("CN", label)
        .map_err(|e| anyhow::anyhow!("Failed to set CN: {}", e))?;
    let name = name_builder.build();

    let mut cert_builder = X509Builder::new()
        .map_err(|e| anyhow::anyhow!("Failed to create X509 builder: {}", e))?;
    cert_builder
        .set_version(2)
        .map_err(|e| anyhow::anyhow!("Failed to set certificate version: {}", e))?;

    let serial = BigNum::from_u32(1)
        .and_then(|bn| bn.to_asn1_integer())
        .map_err(|e| anyhow::anyhow!("Failed to create serial number: {}", e))?;
    cert_builder
        .set_serial_number(&serial)
        .map_err(|e| anyhow::anyhow!("Failed to set serial: {}", e))?;

    cert_builder
        .set_subject_name(&name)
        .map_err(|e| anyhow::anyhow!("Failed to set subject: {}", e))?;
    cert_builder
        .set_issuer_name(&name)
        .map_err(|e| anyhow::anyhow!("Failed to set issuer: {}", e))?;
    cert_builder
        .set_pubkey(&pkey)
        .map_err(|e| anyhow::anyhow!("Failed to set public key: {}", e))?;

    let not_before = openssl::asn1::Asn1Time::days_from_now(0)
        .map_err(|e| anyhow::anyhow!("Failed to create not_before: {}", e))?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(3650)
        .map_err(|e| anyhow::anyhow!("Failed to create not_after: {}", e))?;
    cert_builder
        .set_not_before(&not_before)
        .map_err(|e| anyhow::anyhow!("Failed to set not_before: {}", e))?;
    cert_builder
        .set_not_after(&not_after)
        .map_err(|e| anyhow::anyhow!("Failed to set not_after: {}", e))?;

    cert_builder
        .sign(&pkey, MessageDigest::sha256())
        .map_err(|e| anyhow::anyhow!("Failed to sign certificate: {}", e))?;
    let cert = cert_builder.build();

    // Build the PKCS12 (encrypted in memory, key never touches disk unencrypted)
    let mut p12_builder = openssl::pkcs12::Pkcs12::builder();
    p12_builder.name(label);
    p12_builder.pkey(&pkey);
    p12_builder.cert(&cert);
    let p12 = p12_builder
        .build2(&p12_pass)
        .map_err(|e| anyhow::anyhow!("Failed to build PKCS12: {}", e))?;
    let p12_der = p12
        .to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode PKCS12: {}", e))?;

    // Write the encrypted PKCS12 to a temp file for sc_auth
    let import_result = with_secure_temp_file("p12", &p12_der, |p12_path| {
        let access_str = match access_type {
            AsfAccessType::None => "none",
            AsfAccessType::Bio => "bio",
        };

        let output = Command::new("sc_auth")
            .arg("import-ctk-identities")
            .arg("-f")
            .arg(p12_path)
            .arg("-t")
            .arg(access_str)
            .arg("-p")
            .arg(&p12_pass)
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute sc_auth: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("sc_auth import-ctk-identities failed: {}", stderr.trim());
        }

        Ok(())
    });

    p12_pass.zeroize();

    import_result
}

impl CommandAsfImport {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        match self {
            CommandAsfImport::Ecc {
                curve,
                label,
                access_type,
                dry_run,
            } => {
                let curve_name = normalize_asf_curve_name(curve)?;

                let tool_state = tool_state.as_mut();
                let keypath = tool_state.get_keypath()?;

                // Compute label: use provided value or default to "<ROOT_ID>:<KEYPATH>"
                let label = match label {
                    Some(l) => l.clone(),
                    None => {
                        let root_id = tool_state.root_secret()?.id();
                        format!("{}:{}", root_id, keypath)
                    }
                };

                let secret = tool_state.current_secret()?;
                let secret_key = secret.extract_ec_v1_private_p256()?;

                // Show compressed public key for identification
                {
                    use elliptic_curve::sec1::ToEncodedPoint;
                    let public_key = secret_key.public_key();
                    let compressed = public_key.to_encoded_point(true);
                    let pub_hex = hex::encode(compressed.as_bytes());
                    writeln!(out, "Curve: P-256 ({})", curve_name)?;
                    writeln!(out, "Public key: {}", pub_hex)?;
                    writeln!(out, "Label: {}", label)?;
                    writeln!(out, "Access: {}", access_type)?;
                }

                if *dry_run {
                    writeln!(out, "(dry run -- not importing)")?;
                    return Ok(());
                }

                sc_auth_import(&secret_key, &label, access_type)?;

                // Track in key_map
                tool_state
                    .key_map_mut()
                    .update(keypath)
                    .unwrap()
                    .add_primitive("asf-import:prime256v1");

                writeln!(out, "Key imported to macOS Keychain.")?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_asf_curve_name() {
        assert_eq!(normalize_asf_curve_name("p256").unwrap(), "prime256v1");
        assert_eq!(normalize_asf_curve_name("p-256").unwrap(), "prime256v1");
        assert_eq!(normalize_asf_curve_name("prime256v1").unwrap(), "prime256v1");
        assert_eq!(normalize_asf_curve_name("nistp256").unwrap(), "prime256v1");
        assert_eq!(normalize_asf_curve_name("secp256r1").unwrap(), "prime256v1");
        assert!(normalize_asf_curve_name("ed25519").is_err());
        assert!(normalize_asf_curve_name("secp384r1").is_err());
    }
}
