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

use yubikey::{
    certificate::{CertInfo, Certificate},
    piv::{self, AlgorithmId, RetiredSlotId, SlotId},
    MgmKey, PinPolicy, TouchPolicy, YubiKey,
};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Environment variable names
// ---------------------------------------------------------------------------

/// Management key override (48 hex chars for 3DES).
const ENV_MGM_KEY: &str = "MSECRET_YUBIKEY_MGM_KEY";

/// Default PC/SC reader name substring.
const ENV_READER: &str = "MSECRET_YUBIKEY_READER";

/// Default PIN (prefer interactive prompt; this is for scripting only).
const ENV_PIN: &str = "MSECRET_YUBIKEY_PIN";

/// Length of a 3DES management key in bytes.
const MGM_KEY_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Policy enums (thin wrappers for clap)
// ---------------------------------------------------------------------------

/// PIN policy for the key slot.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum PivPinPolicy {
    /// Use device default (typically "once").
    Default,
    /// Never require PIN for operations with this key.
    Never,
    /// Require PIN once per session.
    Once,
    /// Require PIN before every operation.
    Always,
}

impl From<PivPinPolicy> for PinPolicy {
    fn from(p: PivPinPolicy) -> Self {
        match p {
            PivPinPolicy::Default => PinPolicy::Default,
            PivPinPolicy::Never => PinPolicy::Never,
            PivPinPolicy::Once => PinPolicy::Once,
            PivPinPolicy::Always => PinPolicy::Always,
        }
    }
}

/// Touch (button) policy for the key slot.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum PivTouchPolicy {
    /// Use device default (typically "never").
    Default,
    /// Never require touch for operations with this key.
    Never,
    /// Require touch before every operation.
    Always,
    /// Require touch once; cache for 15 seconds.
    Cached,
}

impl From<PivTouchPolicy> for TouchPolicy {
    fn from(p: PivTouchPolicy) -> Self {
        match p {
            PivTouchPolicy::Default => TouchPolicy::Default,
            PivTouchPolicy::Never => TouchPolicy::Never,
            PivTouchPolicy::Always => TouchPolicy::Always,
            PivTouchPolicy::Cached => TouchPolicy::Cached,
        }
    }
}

// ---------------------------------------------------------------------------
// Command structs
// ---------------------------------------------------------------------------

/// Import a derived key into a YubiKey PIV slot or manage YubiKey PIV state.
#[derive(Debug, clap::Subcommand, Clone)]
pub enum CommandYubikey {
    /// Import a derived private key into a PIV slot.
    #[command(subcommand)]
    Import(CommandYubikeyImport),

    /// Generate and store a self-signed certificate for an existing key in a PIV slot.
    ///
    /// Useful after importing with --no-cert, or to update the certificate label.
    /// The certificate is signed using the same derived key (requires a secret to be loaded).
    Cert {
        /// PIV slot containing the key (9a, 9c, 9d, 9e, or 82-95).
        slot: String,

        /// ECC curve or RSA bit size used when the key was imported (e.g. p256, 2048).
        /// Required so the key can be re-derived for certificate signing.
        #[arg(long)]
        key_type: String,

        /// Certificate Common Name (CN). Defaults to "<SECRET_ID>:<KEYPATH>".
        #[arg(short, long)]
        label: Option<String>,

        /// PC/SC reader name (substring match). Falls back to MSECRET_YUBIKEY_READER env var.
        #[arg(long)]
        reader: Option<String>,

        /// Management key in hex. Falls back to MSECRET_YUBIKEY_MGM_KEY env var, then default.
        #[arg(long = "mgm-key")]
        mgm_key: Option<String>,
    },

    /// List all connected YubiKeys and their PIV slot contents.
    List {
        /// PC/SC reader name (substring match). Falls back to MSECRET_YUBIKEY_READER env var.
        #[arg(long)]
        reader: Option<String>,
    },

    /// Display YubiKey device information.
    Info {
        /// PC/SC reader name (substring match). Falls back to MSECRET_YUBIKEY_READER env var.
        #[arg(long)]
        reader: Option<String>,
    },
}

/// Key type to import into a PIV slot.
#[derive(Debug, clap::Subcommand, Clone)]
pub enum CommandYubikeyImport {
    /// Import a derived ECC private key (P-256, P-384, Ed25519, or X25519).
    ///
    /// Ed25519 and X25519 require YubiKey 5 with firmware 5.7+.
    Ecc {
        /// Curve name: p256, p384, ed25519, or x25519.
        curve: String,

        /// PIV slot to import into (9a, 9c, 9d, 9e, or 82-95). Required.
        #[arg(long)]
        slot: String,

        /// PIV PIN. Falls back to MSECRET_YUBIKEY_PIN env var, then interactive prompt.
        #[arg(long)]
        pin: Option<String>,

        /// Management key in hex. Falls back to MSECRET_YUBIKEY_MGM_KEY env var, then default.
        #[arg(long = "mgm-key")]
        mgm_key: Option<String>,

        /// PIN policy for the imported key.
        #[arg(long = "pin-policy", default_value = "default")]
        pin_policy: PivPinPolicy,

        /// Touch (button) policy for the imported key.
        #[arg(long = "touch-policy", default_value = "default")]
        touch_policy: PivTouchPolicy,

        /// PC/SC reader name (substring match). Falls back to MSECRET_YUBIKEY_READER env var.
        #[arg(long)]
        reader: Option<String>,

        /// Do not generate or store a self-signed certificate alongside the key.
        #[arg(long = "no-cert")]
        no_cert: bool,

        /// Overwrite an existing key in the slot without prompting.
        #[arg(long)]
        force: bool,

        /// Print what would be imported without writing to the YubiKey.
        #[arg(long = "dry-run")]
        dry_run: bool,
    },

    /// Import a derived RSA private key (2048, 3072, or 4096 bits).
    ///
    /// RSA 3072 and 4096 require YubiKey 5 with firmware 5.7+.
    Rsa {
        /// Key size in bits: 2048, 3072, or 4096.
        bits: u16,

        /// PIV slot to import into (9a, 9c, 9d, 9e, or 82-95). Required.
        #[arg(long)]
        slot: String,

        /// PIV PIN. Falls back to MSECRET_YUBIKEY_PIN env var, then interactive prompt.
        #[arg(long)]
        pin: Option<String>,

        /// Management key in hex. Falls back to MSECRET_YUBIKEY_MGM_KEY env var, then default.
        #[arg(long = "mgm-key")]
        mgm_key: Option<String>,

        /// PIN policy for the imported key.
        #[arg(long = "pin-policy", default_value = "default")]
        pin_policy: PivPinPolicy,

        /// Touch (button) policy for the imported key.
        #[arg(long = "touch-policy", default_value = "default")]
        touch_policy: PivTouchPolicy,

        /// PC/SC reader name (substring match). Falls back to MSECRET_YUBIKEY_READER env var.
        #[arg(long)]
        reader: Option<String>,

        /// Do not generate or store a self-signed certificate alongside the key.
        #[arg(long = "no-cert")]
        no_cert: bool,

        /// Overwrite an existing key in the slot without prompting.
        #[arg(long)]
        force: bool,

        /// Print what would be imported without writing to the YubiKey.
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
}

// ---------------------------------------------------------------------------
// Helper: resolve flags with env-var fallback
// ---------------------------------------------------------------------------

/// Resolve management key: flag -> env var -> default (with warning).
fn resolve_mgm_key<W: Write>(mgm_key_flag: Option<&str>, out: &mut W) -> Result<MgmKey, Error> {
    let hex_str = mgm_key_flag
        .map(str::to_string)
        .or_else(|| std::env::var(ENV_MGM_KEY).ok());

    match hex_str {
        Some(s) => {
            let bytes = hex::decode(s.trim())
                .map_err(|e| anyhow::anyhow!("Invalid management key (expected hex): {}", e))?;
            ensure!(
                bytes.len() == MGM_KEY_LEN,
                "Management key must be {} hex bytes ({} hex chars), got {} bytes.",
                MGM_KEY_LEN,
                MGM_KEY_LEN * 2,
                bytes.len()
            );
            let mut key_array = [0u8; MGM_KEY_LEN];
            key_array.copy_from_slice(&bytes);
            let mgm = MgmKey::from_bytes(&key_array, None)
                .map_err(|e| anyhow::anyhow!("Invalid management key: {:?}", e))?;
            key_array.zeroize();
            Ok(mgm)
        }
        None => {
            writeln!(
                out,
                "Warning: Using default management key (3DES). \
                 Set {} or --mgm-key to use a custom key.",
                ENV_MGM_KEY
            )?;
            // Well-known default management key used by YubiKey factory settings.
            let default_bytes: [u8; 24] = [
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
            ];
            MgmKey::from_bytes(&default_bytes, None)
                .map_err(|e| anyhow::anyhow!("Failed to construct default management key: {:?}", e))
        }
    }
}

/// Resolve reader: flag -> env var -> None (first available).
fn resolve_reader(reader_flag: Option<&str>) -> Option<String> {
    reader_flag
        .map(str::to_string)
        .or_else(|| std::env::var(ENV_READER).ok())
}

/// Resolve PIN: flag -> env var -> interactive prompt.
fn resolve_pin(pin_flag: Option<&str>) -> Result<Vec<u8>, Error> {
    let pin_str = if let Some(p) = pin_flag {
        p.to_string()
    } else if let Ok(p) = std::env::var(ENV_PIN) {
        p
    } else {
        rpassword::prompt_password("YubiKey PIN: ")
            .map_err(|e| anyhow::anyhow!("Failed to read PIN: {}", e))?
    };
    Ok(pin_str.into_bytes())
}

// ---------------------------------------------------------------------------
// Helper: open YubiKey
// ---------------------------------------------------------------------------

/// Open a YubiKey, optionally selecting by reader name substring.
fn open_yubikey(reader_name: Option<String>) -> Result<YubiKey, Error> {
    match reader_name {
        None => YubiKey::open().map_err(|e| anyhow::anyhow!("Failed to open YubiKey: {:?}", e)),
        Some(target) => {
            let mut context = yubikey::reader::Context::open()
                .map_err(|e| anyhow::anyhow!("Failed to open PC/SC context: {:?}", e))?;
            for reader in context
                .iter()
                .map_err(|e| anyhow::anyhow!("Failed to list PC/SC readers: {:?}", e))?
            {
                if reader.name().contains(target.as_str()) {
                    return reader
                        .open()
                        .map_err(|e| anyhow::anyhow!("Failed to open reader {:?}: {:?}", target, e));
                }
            }
            bail!(
                "No PC/SC reader found matching {:?}. \
                 Use `yubikey list` to see available readers.",
                target
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: parse PIV slot
// ---------------------------------------------------------------------------

/// Parse a slot string like "9a", "9c", "9d", "9e", or "82"-"95" into a `SlotId`.
pub fn parse_slot(s: &str) -> Result<SlotId, Error> {
    match s.to_lowercase().as_str() {
        "9a" => Ok(SlotId::Authentication),
        "9c" => Ok(SlotId::Signature),
        "9d" => Ok(SlotId::KeyManagement),
        "9e" => Ok(SlotId::CardAuthentication),
        other => {
            let byte = u8::from_str_radix(other, 16).map_err(|_| {
                anyhow::anyhow!(
                    "Invalid slot {:?}. Expected 9a, 9c, 9d, 9e, or 82-95.",
                    s
                )
            })?;
            let retired = RetiredSlotId::try_from(byte).map_err(|_| {
                anyhow::anyhow!(
                    "Invalid retired slot byte 0x{:02x}. Expected 0x82-0x95.",
                    byte
                )
            })?;
            Ok(SlotId::Retired(retired))
        }
    }
}

/// Human-readable slot name.
fn slot_name(slot: SlotId) -> String {
    match slot {
        SlotId::Authentication => "9a (PIV Authentication)".to_string(),
        SlotId::Signature => "9c (Digital Signature)".to_string(),
        SlotId::KeyManagement => "9d (Key Management)".to_string(),
        SlotId::CardAuthentication => "9e (Card Authentication)".to_string(),
        SlotId::Retired(r) => format!("{:02x} (Retired Key Management)", u8::from(r)),
        SlotId::Attestation => "f9 (Attestation)".to_string(),
        _ => format!("{:?}", slot),
    }
}

/// Short slot identifier for KeyMap tracking (e.g. "9a").
fn slot_short(slot: SlotId) -> String {
    match slot {
        SlotId::Authentication => "9a".to_string(),
        SlotId::Signature => "9c".to_string(),
        SlotId::KeyManagement => "9d".to_string(),
        SlotId::CardAuthentication => "9e".to_string(),
        SlotId::Retired(r) => format!("{:02x}", u8::from(r)),
        SlotId::Attestation => "f9".to_string(),
        _ => format!("{:?}", slot),
    }
}

// ---------------------------------------------------------------------------
// Helper: check slot occupancy
// ---------------------------------------------------------------------------

/// Returns true if the slot already has a certificate stored.
fn is_slot_occupied(yk: &mut YubiKey, slot: SlotId) -> bool {
    Certificate::read(yk, slot).is_ok()
}

// ---------------------------------------------------------------------------
// Helper: ECC curve parsing
// ---------------------------------------------------------------------------

/// Normalized ECC curve descriptor used internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    P256,
    P384,
    Ed25519,
    X25519,
}

impl EccCurve {
    pub fn algorithm_id(self) -> AlgorithmId {
        match self {
            EccCurve::P256 => AlgorithmId::EccP256,
            EccCurve::P384 => AlgorithmId::EccP384,
            EccCurve::Ed25519 => AlgorithmId::Ed25519,
            EccCurve::X25519 => AlgorithmId::X25519,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            EccCurve::P256 => "P-256 (prime256v1)",
            EccCurve::P384 => "P-384 (secp384r1)",
            EccCurve::Ed25519 => "Ed25519",
            EccCurve::X25519 => "X25519",
        }
    }

    pub fn keymap_name(self) -> &'static str {
        match self {
            EccCurve::P256 => "prime256v1",
            EccCurve::P384 => "secp384r1",
            EccCurve::Ed25519 => "ed25519",
            EccCurve::X25519 => "x25519",
        }
    }

    /// Returns true if this curve uses the Curve25519 import path (`import_cv_key`).
    pub fn is_curve25519(self) -> bool {
        matches!(self, EccCurve::Ed25519 | EccCurve::X25519)
    }
}

/// Parse an ECC curve name string into an `EccCurve`.
pub fn parse_ecc_curve(s: &str) -> Result<EccCurve, Error> {
    match s.to_lowercase().as_str() {
        "p256" | "p-256" | "prime256v1" | "nistp256" | "secp256r1" => Ok(EccCurve::P256),
        "p384" | "p-384" | "prime384v1" | "nistp384" | "secp384r1" => Ok(EccCurve::P384),
        "ed25519" => Ok(EccCurve::Ed25519),
        "x25519" => Ok(EccCurve::X25519),
        _ => bail!(
            "Unknown or unsupported curve {:?}. Supported: p256, p384, ed25519, x25519.",
            s
        ),
    }
}

// ---------------------------------------------------------------------------
// Helper: certificate generation (requires openssl feature)
// ---------------------------------------------------------------------------

/// Build and return a DER-encoded self-signed X.509 certificate for an ECC key.
#[cfg(feature = "openssl")]
fn build_ecc_cert_der<D: Ecc>(label: &str, curve: EccCurve, secret: &D) -> Result<Vec<u8>, Error> {
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey, EcPoint},
        nid::Nid,
        pkey::{Id, PKey},
    };

    let pkey = match curve {
        EccCurve::P256 => {
            let sk = secret.extract_ec_v1_private_p256()?;
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let private_bn = BigNum::from_slice(sk.to_bytes().as_slice())?;
            let ctx = BigNumContext::new()?;
            let mut public_point = EcPoint::new(&group)?;
            public_point.mul_generator(&group, &private_bn, &ctx)?;
            let ec_key = EcKey::from_private_components(&group, &private_bn, &public_point)?;
            ec_key.check_key()?;
            PKey::from_ec_key(ec_key)?
        }
        EccCurve::P384 => {
            let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
            let ec_key = secret.extract_ec_v1_private_openssl(&group)?;
            PKey::from_ec_key(ec_key)?
        }
        EccCurve::Ed25519 => {
            let sk = secret.extract_ed25519_private()?;
            PKey::private_key_from_raw_bytes(&sk.to_bytes(), Id::ED25519)?
        }
        EccCurve::X25519 => {
            bail!(
                "X25519 is a key-agreement algorithm and cannot self-sign certificates. \
                 Use --no-cert when importing X25519 keys."
            );
        }
    };

    build_cert_der(label, &pkey)
}

/// Build and return a DER-encoded self-signed X.509 certificate for an RSA key.
#[cfg(feature = "openssl")]
fn build_rsa_cert_der<D: ExtractRsaV1>(label: &str, bits: u16, secret: &D) -> Result<Vec<u8>, Error> {
    use openssl::pkey::PKey;
    let rsa = secret.extract_rsa_v1_private_openssl(bits)?;
    let pkey = PKey::from_rsa(rsa)?;
    build_cert_der(label, &pkey)
}

/// Shared certificate building logic: produce a DER-encoded self-signed X.509 cert.
#[cfg(feature = "openssl")]
fn build_cert_der(
    label: &str,
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> Result<Vec<u8>, Error> {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        x509::{X509Builder, X509NameBuilder},
    };

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", label)?;
    let name = name_builder.build();

    let mut cert_builder = X509Builder::new()?;
    cert_builder.set_version(2)?;

    let serial = BigNum::from_u32(1).and_then(|bn| bn.to_asn1_integer())?;
    cert_builder.set_serial_number(&serial)?;
    cert_builder.set_subject_name(&name)?;
    cert_builder.set_issuer_name(&name)?;
    cert_builder.set_pubkey(pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    cert_builder.set_not_before(&not_before)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.sign(pkey, MessageDigest::sha256())?;

    let cert = cert_builder.build();
    Ok(cert.to_der()?)
}

/// Write a DER certificate to a YubiKey slot.
fn write_cert(yk: &mut YubiKey, slot: SlotId, der: Vec<u8>) -> Result<(), Error> {
    let cert = Certificate::from_bytes(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;
    cert.write(yk, slot, CertInfo::Uncompressed)
        .map_err(|e| anyhow::anyhow!("Failed to write certificate to slot: {:?}", e))
}

// ---------------------------------------------------------------------------
// Helper: display slot contents
// ---------------------------------------------------------------------------

fn print_slot_info<W: Write>(yk: &mut YubiKey, slot: SlotId, out: &mut W) -> Result<(), Error> {
    match Certificate::read(yk, slot) {
        Ok(_cert) => {
            writeln!(out, "  Slot {}: has certificate", slot_name(slot))?;
        }
        Err(_) => {
            writeln!(out, "  Slot {}: (empty)", slot_name(slot))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// process() implementation
// ---------------------------------------------------------------------------

impl CommandYubikey {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        match self {
            CommandYubikey::Import(import_cmd) => import_cmd.process(tool_state, out),

            CommandYubikey::Cert {
                slot,
                key_type,
                label,
                reader,
                mgm_key,
            } => {
                let tool_state = tool_state.as_mut();
                let keypath = tool_state.get_keypath()?;
                let secret = tool_state.current_secret()?;

                let slot_id = parse_slot(slot)?;
                let reader_name = resolve_reader(reader.as_deref());
                let mgm = resolve_mgm_key(mgm_key.as_deref(), out)?;

                let cert_label = match label {
                    Some(l) => l.clone(),
                    None => {
                        let root_id = tool_state.root_secret()?.id();
                        format!("{}:{}", root_id, keypath)
                    }
                };

                #[cfg(not(feature = "openssl"))]
                bail!("Certificate generation requires the 'openssl' feature.");

                #[cfg(feature = "openssl")]
                {
                    let der = match parse_ecc_curve(key_type) {
                        Ok(curve) => build_ecc_cert_der(&cert_label, curve, &secret)?,
                        Err(_) => {
                            let bits: u16 = key_type.parse().map_err(|_| {
                                anyhow::anyhow!(
                                    "Unknown key type {:?}. Expected a curve name \
                                     (p256, p384, ed25519) or RSA bit size (2048, 3072, 4096).",
                                    key_type
                                )
                            })?;
                            build_rsa_cert_der(&cert_label, bits, &secret)?
                        }
                    };

                    let mut yk = open_yubikey(reader_name)?;
                    yk.authenticate(&mgm)
                        .map_err(|e| anyhow::anyhow!("Management key authentication failed: {:?}", e))?;
                    write_cert(&mut yk, slot_id, der)?;
                    writeln!(
                        out,
                        "Certificate written to slot {}: CN={}",
                        slot_short(slot_id),
                        cert_label
                    )?;
                }

                Ok(())
            }

            CommandYubikey::List { reader } => {
                let reader_name = resolve_reader(reader.as_deref());
                let mut yk = open_yubikey(reader_name)?;

                writeln!(
                    out,
                    "YubiKey (serial: {}, firmware: {})",
                    yk.serial(),
                    yk.version()
                )?;

                for slot in &[
                    SlotId::Authentication,
                    SlotId::Signature,
                    SlotId::KeyManagement,
                    SlotId::CardAuthentication,
                ] {
                    print_slot_info(&mut yk, *slot, out)?;
                }

                Ok(())
            }

            CommandYubikey::Info { reader } => {
                let reader_name = resolve_reader(reader.as_deref());
                let yk = open_yubikey(reader_name)?;

                writeln!(out, "Serial:   {}", yk.serial())?;
                writeln!(out, "Firmware: {}", yk.version())?;
                writeln!(out, "Name:     {}", yk.name())?;

                Ok(())
            }
        }
    }
}

impl CommandYubikeyImport {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        match self {
            CommandYubikeyImport::Ecc {
                curve,
                slot,
                pin,
                mgm_key,
                pin_policy,
                touch_policy,
                reader,
                no_cert,
                force,
                dry_run,
            } => {
                let curve = parse_ecc_curve(curve)?;
                let slot_id = parse_slot(slot)?;
                let reader_name = resolve_reader(reader.as_deref());

                let tool_state = tool_state.as_mut();
                let keypath = tool_state.get_keypath()?;
                let secret = tool_state.current_secret()?;

                let (key_bytes, pubkey_hex) = extract_ecc_key_bytes(&secret, curve)?;

                let cert_label = {
                    let root_id = tool_state.root_secret()?.id();
                    format!("{}:{}", root_id, keypath)
                };

                writeln!(out, "Curve:         {}", curve.display_name())?;
                writeln!(out, "Public key:    {}", pubkey_hex)?;
                writeln!(out, "Slot:          {}", slot_name(slot_id))?;
                writeln!(out, "Pin policy:    {:?}", pin_policy)?;
                writeln!(out, "Touch policy:  {:?}", touch_policy)?;
                writeln!(
                    out,
                    "Certificate:   {}",
                    if *no_cert { "(none)" } else { &cert_label }
                )?;

                if *dry_run {
                    writeln!(out, "(dry run -- not importing)")?;
                    return Ok(());
                }

                let mut yk = open_yubikey(reader_name)?;

                if !force && is_slot_occupied(&mut yk, slot_id) {
                    bail!(
                        "Slot {} already contains a key. Use --force to overwrite.",
                        slot_name(slot_id)
                    );
                } else if *force && is_slot_occupied(&mut yk, slot_id) {
                    writeln!(
                        out,
                        "Warning: Overwriting existing key in slot {}.",
                        slot_name(slot_id)
                    )?;
                }

                let mgm = resolve_mgm_key(mgm_key.as_deref(), out)?;
                yk.authenticate(&mgm)
                    .map_err(|e| anyhow::anyhow!("Management key authentication failed: {:?}", e))?;

                let mut pin_bytes = resolve_pin(pin.as_deref())?;
                yk.verify_pin(&pin_bytes).map_err(|e| {
                    pin_bytes.zeroize();
                    anyhow::anyhow!("PIN verification failed: {:?}", e)
                })?;
                pin_bytes.zeroize();

                if curve.is_curve25519() {
                    piv::import_cv_key(
                        &mut yk,
                        slot_id,
                        curve.algorithm_id(),
                        &key_bytes,
                        touch_policy.clone().into(),
                        pin_policy.clone().into(),
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to import Curve25519 key: {:?}", e))?;
                } else {
                    piv::import_ecc_key(
                        &mut yk,
                        slot_id,
                        curve.algorithm_id(),
                        &key_bytes,
                        touch_policy.clone().into(),
                        pin_policy.clone().into(),
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to import ECC key: {:?}", e))?;
                }

                if !no_cert {
                    #[cfg(feature = "openssl")]
                    {
                        let der = build_ecc_cert_der(&cert_label, curve, &secret)?;
                        write_cert(&mut yk, slot_id, der)?;
                        writeln!(out, "Certificate:   CN={}", cert_label)?;
                    }
                    #[cfg(not(feature = "openssl"))]
                    writeln!(
                        out,
                        "Note: Certificate generation requires the 'openssl' feature. \
                         Key imported without certificate."
                    )?;
                }

                tool_state
                    .key_map_mut()
                    .update(&keypath)
                    .unwrap()
                    .add_primitive(&format!(
                        "yubikey-piv-{}:{}",
                        slot_short(slot_id),
                        curve.keymap_name()
                    ));

                writeln!(
                    out,
                    "Key imported to YubiKey (serial: {}), slot {}.",
                    yk.serial(),
                    slot_name(slot_id)
                )?;
                Ok(())
            }

            CommandYubikeyImport::Rsa {
                bits,
                slot,
                pin,
                mgm_key,
                pin_policy,
                touch_policy,
                reader,
                no_cert,
                force,
                dry_run,
            } => {
                let slot_id = parse_slot(slot)?;
                let reader_name = resolve_reader(reader.as_deref());

                let algorithm_id = match bits {
                    2048 => AlgorithmId::Rsa2048,
                    3072 => AlgorithmId::Rsa3072,
                    4096 => AlgorithmId::Rsa4096,
                    _ => bail!(
                        "Unsupported RSA key size {}. Supported: 2048, 3072, 4096.",
                        bits
                    ),
                };

                let tool_state = tool_state.as_mut();
                let keypath = tool_state.get_keypath()?;

                #[cfg(not(feature = "openssl"))]
                bail!("RSA key import requires the 'openssl' feature.");

                #[cfg(feature = "openssl")]
                {
                    let secret = tool_state.current_secret()?;
                    let rsa = secret.extract_rsa_v1_private_openssl(*bits)?;

                    let key_data = rsa_to_key_data(&rsa)?;

                    let pubkey_hex = hex::encode(rsa.n().to_vec());

                    let cert_label = {
                        let root_id = tool_state.root_secret()?.id();
                        format!("{}:{}", root_id, keypath)
                    };

                    writeln!(out, "Algorithm:     RSA-{}", bits)?;
                    writeln!(
                        out,
                        "Modulus:       {}...",
                        &pubkey_hex[..std::cmp::min(16, pubkey_hex.len())]
                    )?;
                    writeln!(out, "Slot:          {}", slot_name(slot_id))?;
                    writeln!(out, "Pin policy:    {:?}", pin_policy)?;
                    writeln!(out, "Touch policy:  {:?}", touch_policy)?;
                    writeln!(
                        out,
                        "Certificate:   {}",
                        if *no_cert { "(none)" } else { &cert_label }
                    )?;

                    if *dry_run {
                        writeln!(out, "(dry run -- not importing)")?;
                        return Ok(());
                    }

                    let mut yk = open_yubikey(reader_name)?;

                    if !force && is_slot_occupied(&mut yk, slot_id) {
                        bail!(
                            "Slot {} already contains a key. Use --force to overwrite.",
                            slot_name(slot_id)
                        );
                    } else if *force && is_slot_occupied(&mut yk, slot_id) {
                        writeln!(
                            out,
                            "Warning: Overwriting existing key in slot {}.",
                            slot_name(slot_id)
                        )?;
                    }

                    let mgm = resolve_mgm_key(mgm_key.as_deref(), out)?;
                    yk.authenticate(&mgm)
                        .map_err(|e| anyhow::anyhow!("Management key authentication failed: {:?}", e))?;

                    let mut pin_bytes = resolve_pin(pin.as_deref())?;
                    yk.verify_pin(&pin_bytes).map_err(|e| {
                        pin_bytes.zeroize();
                        anyhow::anyhow!("PIN verification failed: {:?}", e)
                    })?;
                    pin_bytes.zeroize();

                    piv::import_rsa_key(
                        &mut yk,
                        slot_id,
                        algorithm_id,
                        key_data,
                        touch_policy.clone().into(),
                        pin_policy.clone().into(),
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to import RSA key: {:?}", e))?;

                    if !no_cert {
                        let der = build_rsa_cert_der(&cert_label, *bits, &secret)?;
                        write_cert(&mut yk, slot_id, der)?;
                        writeln!(out, "Certificate:   CN={}", cert_label)?;
                    }

                    tool_state
                        .key_map_mut()
                        .update(&keypath)
                        .unwrap()
                        .add_primitive(&format!("yubikey-piv-{}:rsa{}", slot_short(slot_id), bits));

                    writeln!(
                        out,
                        "Key imported to YubiKey (serial: {}), slot {}.",
                        yk.serial(),
                        slot_name(slot_id)
                    )?;
                }

                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key extraction helpers
// ---------------------------------------------------------------------------

/// Extract raw private key bytes and a compressed public key hex string for
/// the given ECC curve from the current secret.
fn extract_ecc_key_bytes<D: Ecc>(
    secret: &D,
    curve: EccCurve,
) -> Result<(Vec<u8>, String), Error> {
    match curve {
        EccCurve::P256 => {
            use elliptic_curve::sec1::ToEncodedPoint;
            let sk = secret.extract_ec_v1_private_p256()?;
            let key_bytes = sk.to_bytes().to_vec();
            let pub_hex = hex::encode(sk.public_key().to_encoded_point(true).as_bytes());
            Ok((key_bytes, pub_hex))
        }
        EccCurve::P384 => {
            #[cfg(feature = "openssl")]
            {
                use openssl::{bn::BigNumContext, ec::EcGroup, nid::Nid};
                let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
                let sk = secret.extract_ec_v1_private_openssl(&group)?;
                let key_bytes = sk.private_key().to_vec();
                let mut ctx = BigNumContext::new()?;
                let pub_bytes = sk.public_key().to_bytes(
                    &group,
                    openssl::ec::PointConversionForm::COMPRESSED,
                    &mut ctx,
                )?;
                Ok((key_bytes, hex::encode(pub_bytes)))
            }
            #[cfg(not(feature = "openssl"))]
            bail!("P-384 requires the 'openssl' feature.")
        }
        EccCurve::Ed25519 => {
            let sk = secret.extract_ed25519_private()?;
            let vk = sk.verifying_key();
            let key_bytes = sk.to_bytes().to_vec();
            let pub_hex = hex::encode(vk.as_bytes());
            Ok((key_bytes, pub_hex))
        }
        EccCurve::X25519 => {
            let sk_bytes = secret.extract_x25519_private()?;
            let sk = x25519_dalek::StaticSecret::from(sk_bytes);
            let pk = x25519_dalek::PublicKey::from(&sk);
            let key_bytes = sk_bytes.to_vec();
            let pub_hex = hex::encode(pk.as_bytes());
            Ok((key_bytes, pub_hex))
        }
    }
}

/// Convert an OpenSSL RSA private key into `yubikey::piv::RsaKeyData`.
///
/// `RsaKeyData::new(p, q)` computes the CRT components internally.
#[cfg(feature = "openssl")]
fn rsa_to_key_data(
    rsa: &openssl::rsa::Rsa<openssl::pkey::Private>,
) -> Result<piv::RsaKeyData, Error> {
    let p = rsa
        .p()
        .ok_or_else(|| anyhow::anyhow!("RSA key missing prime p"))?
        .to_vec();
    let q = rsa
        .q()
        .ok_or_else(|| anyhow::anyhow!("RSA key missing prime q"))?
        .to_vec();

    piv::RsaKeyData::new(&p, &q)
        .map_err(|e| anyhow::anyhow!("Failed to construct RsaKeyData: {:?}", e))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_slot() {
        assert!(matches!(parse_slot("9a").unwrap(), SlotId::Authentication));
        assert!(matches!(parse_slot("9c").unwrap(), SlotId::Signature));
        assert!(matches!(parse_slot("9d").unwrap(), SlotId::KeyManagement));
        assert!(matches!(
            parse_slot("9e").unwrap(),
            SlotId::CardAuthentication
        ));
        assert!(matches!(parse_slot("82").unwrap(), SlotId::Retired(_)));
        assert!(matches!(parse_slot("95").unwrap(), SlotId::Retired(_)));
        assert!(parse_slot("96").is_err());
        assert!(parse_slot("foo").is_err());
    }

    #[test]
    fn test_parse_ecc_curve() {
        assert_eq!(parse_ecc_curve("p256").unwrap(), EccCurve::P256);
        assert_eq!(parse_ecc_curve("P-256").unwrap(), EccCurve::P256);
        assert_eq!(parse_ecc_curve("prime256v1").unwrap(), EccCurve::P256);
        assert_eq!(parse_ecc_curve("nistp256").unwrap(), EccCurve::P256);
        assert_eq!(parse_ecc_curve("secp256r1").unwrap(), EccCurve::P256);
        assert_eq!(parse_ecc_curve("p384").unwrap(), EccCurve::P384);
        assert_eq!(parse_ecc_curve("ed25519").unwrap(), EccCurve::Ed25519);
        assert_eq!(parse_ecc_curve("Ed25519").unwrap(), EccCurve::Ed25519);
        assert_eq!(parse_ecc_curve("x25519").unwrap(), EccCurve::X25519);
        assert_eq!(parse_ecc_curve("X25519").unwrap(), EccCurve::X25519);
        assert!(parse_ecc_curve("secp256k1").is_err());
    }
}
