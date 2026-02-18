# Plan: `yubikey` Command — YubiKey PIV Key Import

## Context

MSecret derives deterministic cryptographic keys from a master secret. The existing
`apple-ctk-export` command demonstrates the pattern of importing derived keys into
external secure storage (macOS Keychain). This plan extends that concept to YubiKey
tokens, allowing derived private keys to be loaded into PIV slots on a YubiKey.

This enables workflows like deriving a P-256 authentication key at a specific keypath
and loading it into slot 9a of a YubiKey for use with PIV-aware applications (SSH via
`ssh-agent`, VPN clients, TLS client auth, etc.).

## Feasibility Assessment

**Verdict: Feasible with caveats.**

### Rust `yubikey` Crate

The [`yubikey`](https://crates.io/crates/yubikey) crate (v0.8.x, maintained by
RustCrypto team, originally from iqlusioninc) provides pure-Rust PIV support:

- `YubiKey::open()` — connect to an attached YubiKey via PC/SC
- `yk.authenticate(mgm_key)` — authenticate with the management key (required for import)
- `yk.verify_pin(pin)` — verify the user's PIN
- `piv::import_ecc_key()` — import an ECC private key into a PIV slot
- `piv::import_rsa_key()` — import an RSA private key into a PIV slot

**Important:** The key import functions require the `untested` feature flag, indicating
they have not been thoroughly validated by the crate maintainers. Manual testing against
real hardware will be essential.

### Supported Key Types by YubiKey Model

| Algorithm | YubiKey Neo (FW 3.x) | YubiKey 4 | YubiKey 5 (FW 5.7+) |
|-----------|:--------------------:|:---------:|:--------------------:|
| RSA 1024 | Yes | Yes | Yes |
| RSA 2048 | Yes | Yes | Yes |
| RSA 3072 | No | No | Yes |
| RSA 4096 | No | No | Yes |
| ECC P-256 | Yes* | Yes | Yes |
| ECC P-384 | Yes* | Yes | Yes |
| Ed25519 | No | No | Yes |
| X25519 | No | No | Yes |

*(\*) Firmware-dependent; some Neo firmware may not fully support ECC.*

### PIV Slots

| Slot | Name | Purpose | Neo | YK4/5 |
|------|------|---------|:---:|:-----:|
| 9a | PIV Authentication | Login, SSH, TLS client auth | Yes | Yes |
| 9c | Digital Signature | Document/code signing; PIN required each use | Yes | Yes |
| 9d | Key Management | Encryption/decryption (email, files) | Yes | Yes |
| 9e | Card Authentication | Physical access; no PIN required | Yes | Yes |
| 82–95 | Retired Key Management | 20 additional key management slots | No | Yes |
| f9 | Attestation | Attestation of on-device generated keys | No | 4.3+ |

### YubiKey Neo Limitations

- **4 PIV slots only** (9a, 9c, 9d, 9e)
- **RSA**: 1024 and 2048 only
- **No Ed25519/X25519** (requires firmware 5.7+)
- **Management key**: Triple-DES only (no AES)
- **Max stored object size**: 2,025 bytes
- **Not officially supported** by the Rust `yubikey` crate (targets YK4/5)

## Command Design

### Subcommands

```
yubikey import ecc <CURVE> --slot <SLOT> [--pin <PIN>] [--mgm-key <KEY>]
                           [--pin-policy <POLICY>] [--touch-policy <POLICY>]
                           [--reader <NAME>] [--no-cert] [--force] [--dry-run]

yubikey import rsa <BITS>  --slot <SLOT> [--pin <PIN>] [--mgm-key <KEY>]
                           [--pin-policy <POLICY>] [--touch-policy <POLICY>]
                           [--reader <NAME>] [--no-cert] [--force] [--dry-run]

yubikey cert <SLOT>        [--label <LABEL>] [--reader <NAME>] [--pin <PIN>]
                           [--mgm-key <KEY>]

yubikey list               [--reader <NAME>]

yubikey info               [--reader <NAME>]
```

### Environment Variables

| Variable | Purpose | Overridden by |
|----------|---------|---------------|
| `MSECRET_YUBIKEY_MGM_KEY` | Default management key (hex-encoded) | `--mgm-key` flag |
| `MSECRET_YUBIKEY_READER` | Default PC/SC reader name | `--reader` flag |
| `MSECRET_YUBIKEY_PIN` | Default PIN (use with caution) | `--pin` flag |

**Resolution order** (for management key as example):
1. `--mgm-key` command-line flag (highest priority)
2. `MSECRET_YUBIKEY_MGM_KEY` environment variable
3. Interactive prompt (for PIN only) or YubiKey default key (for management key)

### `yubikey import ecc`

Import a derived ECC private key into a PIV slot.

- `CURVE` (required): ECC curve name. Supported values:
  - `p256` / `prime256v1` / `p-256` / `nistp256` / `secp256r1` — NIST P-256
  - `p384` / `prime384v1` / `p-384` / `nistp384` / `secp384r1` — NIST P-384
  - `ed25519` — Ed25519 (YubiKey 5 firmware 5.7+ only)
  - `x25519` — X25519 (YubiKey 5 firmware 5.7+ only)
- `--slot` (required): PIV slot — `9a`, `9c`, `9d`, `9e`, `82`–`95`
- `--pin`: PIV PIN (prompted interactively if not provided and not in env)
- `--mgm-key`: Management key in hex
- `--pin-policy`: `default`, `never`, `once`, `always` (default: `default`)
- `--touch-policy`: `default`, `never`, `always`, `cached` (default: `default`)
- `--reader`: PC/SC reader name
- `--no-cert`: Skip automatic self-signed certificate generation
- `--force`: Overwrite existing key in slot without prompting
- `--dry-run`: Show key info and slot details without importing

### `yubikey import rsa`

Import a derived RSA private key into a PIV slot.

- `BITS` (required): Key size — `2048`, `3072`, `4096` (3072/4096 require YubiKey 5 FW 5.7+)
- Same optional flags as `ecc`

### `yubikey cert`

Generate and store a self-signed X.509 certificate for an existing key in a PIV slot.
This is useful when a key was imported with `--no-cert`, or to replace/update the
certificate label.

- `SLOT` (required): PIV slot containing the key — `9a`, `9c`, `9d`, `9e`, `82`–`95`
- `--label`: Certificate Common Name (CN). Defaults to `<SECRET_ID>:<KEYPATH>`
- `--reader`: PC/SC reader name
- `--pin`: PIV PIN (needed to sign the certificate with the on-card key)
- `--mgm-key`: Management key (needed to write the certificate object)

The certificate is signed using the private key already in the slot (on-card signing),
so no private key material is needed for this operation.

### `yubikey list`

List all connected YubiKeys and their PIV slot contents (algorithm, certificate subject,
public key fingerprint for populated slots).

### `yubikey info`

Display YubiKey device info: serial number, firmware version, available slots,
algorithms supported, PIN retries remaining.

### Example Session

```
$ export MSECRET_YUBIKEY_MGM_KEY=010203040506070801020304050607080102030405060708
$ msecretctl
> secret passphrase
Passphrase: ********
Imported DCUUx9UhnhJErcndchjMsZ
/> cd /piv/auth
/piv/auth> yubikey import ecc p256 --slot 9a
PIN: ******
Curve:        P-256 (prime256v1)
Public key:   03a1b2c3d4...
Slot:         9a (PIV Authentication)
Pin policy:   default
Touch policy: default
Certificate:  CN=DCUUx9UhnhJErcndchjMsZ:/piv/auth
Key imported to YubiKey (serial: 12345678), slot 9a.

/piv/auth> cd /piv/sign
/piv/sign> yubikey import ecc ed25519 --slot 9c
PIN: ******
Curve:        Ed25519
Public key:   e5f6a7b8c9...
Slot:         9c (Digital Signature)
Key imported to YubiKey (serial: 12345678), slot 9c.

/piv/sign> yubikey list
YubiKey (serial: 12345678, firmware: 5.7.1)
  Slot 9a (PIV Authentication): P-256, CN=DCUUx9UhnhJErcndchjMsZ:/piv/auth
  Slot 9c (Digital Signature):  Ed25519, CN=DCUUx9UhnhJErcndchjMsZ:/piv/sign
  Slot 9d (Key Management):     (empty)
  Slot 9e (Card Authentication): (empty)
```

### Example: Updating a Certificate Label

```
/piv/auth> yubikey cert 9a --label "SSH Authentication Key"
PIN: ******
Certificate written to slot 9a: CN=SSH Authentication Key
```

## Feature Gating

New Cargo feature `yubikey`, not included in defaults (requires hardware):

```toml
[features]
yubikey = ["dep:yubikey"]
```

All YubiKey code gated with: `#[cfg(feature = "yubikey")]`

No OS restriction — the `yubikey` crate uses PC/SC which works on Linux, macOS, and
Windows. However, Linux requires `pcscd` to be running and the `libpcsclite-dev` package
installed.

## Files to Create/Modify

### 1. `Cargo.toml` — Add dependency and feature

```toml
[dependencies]
yubikey = { version = "0.8", features = ["untested"], optional = true }

[features]
yubikey = ["dep:yubikey"]
```

### 2. `src/tool/command/yubikey_cmd.rs` — New file (primary implementation)

Contains:

- **`PivSlot` enum** — `S9a`, `S9c`, `S9d`, `S9e`, `Retired(u8)` with `clap::ValueEnum`,
  mapping to `yubikey::piv::SlotId`
- **`PivPinPolicy` enum** — `Default`, `Never`, `Once`, `Always`
- **`PivTouchPolicy` enum** — `Default`, `Never`, `Always`, `Cached`
- **`CommandYubikey` enum** (clap Subcommand):
  - `Import` (subcommand enum):
    - `Ecc { curve, slot, pin, mgm_key, pin_policy, touch_policy, reader, no_cert, force, dry_run }`
    - `Rsa { bits, slot, pin, mgm_key, pin_policy, touch_policy, reader, no_cert, force, dry_run }`
  - `Cert { slot, label, reader, pin, mgm_key }`
  - `List { reader }`
  - `Info { reader }`
- **`resolve_mgm_key(flag: Option<&str>)`** — check `--mgm-key` flag, then
  `MSECRET_YUBIKEY_MGM_KEY` env var, then fall back to `MgmKey::default()` (with warning)
- **`resolve_reader(flag: Option<&str>)`** — check `--reader` flag, then
  `MSECRET_YUBIKEY_READER` env var
- **`resolve_pin(flag: Option<&str>)`** — check `--pin` flag, then `MSECRET_YUBIKEY_PIN`
  env var, then prompt interactively via `rpassword`
- **`open_yubikey(reader: Option<&str>)`** — connect to a YubiKey, optionally by reader name
- **`check_slot_occupied()`** — check if a slot already has a key; error unless `--force`
- **`generate_self_signed_cert()`** — create an X.509 self-signed certificate for the
  imported key and store it in the same slot
- **`import_ecc_key()`** — authenticate, extract key via `Ecc` trait, import, optionally
  generate cert
- **`import_rsa_key()`** — authenticate, extract RSA key via `ExtractRsaV1` trait,
  convert to `RsaKeyData`, import, optionally generate cert
- **`process()` method** — standard `<T: AsMut<S>, S: ToolState, W: Write>` pattern
- Unit tests for slot/policy parsing, curve normalization, env var resolution

### 3. `src/tool/command/mod.rs` — Register command

- Add conditional `mod yubikey_cmd;` and `pub use yubikey_cmd::*;`
  (using `yubikey_cmd` to avoid name collision with the `yubikey` crate)
- Add `Yubikey(CommandYubikey)` variant to `Command` enum (feature-gated)
- Add match arm in `Command::process()`

### 4. `src/tool/main.rs` — Tab completion

Extend REPL completion to handle:
- `yubikey import ecc <TAB>` — curve names (p256, p384, ed25519, x25519)
- `yubikey import rsa <TAB>` — bit sizes (2048, 3072, 4096)
- `yubikey cert <TAB>` — slot names
- `--slot <TAB>` — slot names (9a, 9c, 9d, 9e, 82–95)

## Key Implementation Details

### ECC Key Import Flow

```
Secret (256-bit)
  ↓ subsecret_from_path(keypath)
Subsecret at keypath
  ↓ extract_ec_v1_private_p256()     — for P-256
  ↓ extract_ec_v1_private_openssl()  — for P-384
  ↓ extract_ed25519_private()        — for Ed25519
  ↓ extract_x25519_private()         — for X25519
Private key
  ↓ .to_bytes() → raw scalar bytes
  ↓ piv::import_ecc_key(&mut yk, slot, algorithm_id, &key_bytes,
  ↓                      touch_policy, pin_policy)
YubiKey PIV slot
  ↓ (unless --no-cert)
  ↓ generate_self_signed_cert() → X.509 cert signed on-card
  ↓ write cert to same slot
YubiKey PIV slot (key + certificate)
```

### RSA Key Import Flow

```
Secret (256-bit)
  ↓ subsecret_from_path(keypath)
Subsecret at keypath
  ↓ extract_rsa_v1(bits)  (ExtractRsaV1 trait, deterministic prime generation)
rsa::RsaPrivateKey
  ↓ Extract CRT components: p, q, dp, dq, qinv
  ↓ Convert to yubikey::piv::RsaKeyData
  ↓ piv::import_rsa_key(&mut yk, slot, algorithm_id, key_data,
  ↓                      touch_policy, pin_policy)
YubiKey PIV slot
  ↓ (unless --no-cert)
  ↓ generate_self_signed_cert() → X.509 cert signed on-card
  ↓ write cert to same slot
YubiKey PIV slot (key + certificate)
```

### Self-Signed Certificate Generation

After importing a key, a self-signed X.509 certificate is generated by default:

1. Build a certificate template with:
   - Subject/Issuer CN = label (default: `<SECRET_ID>:<KEYPATH>`)
   - Serial number = 1
   - Validity = 10 years from now
   - Key usage appropriate to the slot (e.g., digitalSignature for 9c, keyEncipherment
     for 9d)
2. Sign the certificate using the on-card private key via `piv::sign_data()`
3. Store the certificate in the slot via the certificate management API

This ensures the slot is fully usable with PIV applications that require a certificate.

### Management Key Handling

The management key is required for all import and certificate write operations.

**Resolution order:**
1. `--mgm-key` command-line flag (hex-encoded, highest priority)
2. `MSECRET_YUBIKEY_MGM_KEY` environment variable (hex-encoded)
3. Fall back to `MgmKey::default()` with a printed warning:
   `"Warning: Using default management key. Consider changing it for security."`

The management key format:
- 24 bytes hex (48 hex chars) for Triple-DES (all YubiKeys)
- 16/24/32 bytes hex for AES-128/192/256 (YubiKey 5 firmware 5.4+)

### PIN Handling

**Resolution order:**
1. `--pin` command-line flag (highest priority)
2. `MSECRET_YUBIKEY_PIN` environment variable
3. Interactive prompt via `rpassword::prompt_password()`

All PIN material is zeroized after use.

### Slot Overwrite Protection

Before importing a key, check if the target slot already contains a key:

1. Query the slot for existing certificate/key info
2. If occupied and `--force` is not set, print slot contents and error:
   `"Slot 9a already contains a P-256 key. Use --force to overwrite."`
3. If `--force` is set, proceed with a warning:
   `"Warning: Overwriting existing key in slot 9a."`

### Error Handling

Map common `yubikey::Error` variants to actionable messages:

| Error | Message |
|-------|---------|
| `Error::NotFound` | "No YubiKey found. Ensure a YubiKey is connected." |
| `Error::AuthenticationError` | "Management key authentication failed. Check your management key." |
| `Error::PinError { retries }` | "PIN verification failed. {retries} retries remaining." |
| `Error::GenericError` | "YubiKey operation failed: {details}" |
| Algorithm not supported | "This YubiKey does not support {algorithm}. Check firmware version." |
| Slot parse error | "Invalid slot: {value}. Expected 9a, 9c, 9d, 9e, or 82-95." |

### Memory Safety

- All key material (private key bytes, PIN, management key) must be zeroized after use
  via the `zeroize` crate (already a dependency)
- The `yubikey` crate handles zeroization of its internal buffers
- No key material is written to disk at any point (unlike the CTK approach which uses
  PKCS#12 temp files — here the Rust crate communicates directly via PC/SC)

### KeyMap Tracking

After successful import, record the operation:
```rust
tool_state.key_map_mut()
    .update(keypath).unwrap()
    .add_primitive(&format!("yubikey-piv-{}:{}", slot_name, curve_or_bits));
```

## Testing Strategy

### Automated Tests (no hardware required)

- Curve/slot/policy name normalization and parsing
- RSA CRT component extraction and conversion to `RsaKeyData`
- Command argument parsing
- Environment variable resolution logic
- Feature-gate compilation: `cargo build` (without `yubikey`) must succeed
- Feature-gate compilation: `cargo build --features yubikey` must succeed

### Manual Tests (require YubiKey hardware)

1. **ECC P-256 import** to each main slot (9a, 9c, 9d, 9e) — verify key + cert
2. **ECC Ed25519 import** to slot 9a (YubiKey 5 FW 5.7+)
3. **RSA 2048 import** to slot 9a — verify key + cert
4. **`--no-cert`** — verify key imported without certificate
5. **`yubikey cert`** — generate cert for a slot that has key but no cert
6. **Dry-run** shows key info without importing
7. **PIN prompt** works when `--pin` is not provided
8. **Env var management key** — set `MSECRET_YUBIKEY_MGM_KEY` and verify import works
9. **Env var reader** — set `MSECRET_YUBIKEY_READER` and verify device selection
10. **Slot overwrite protection** — attempt import to occupied slot without `--force`
11. **`--force` overwrite** — import to occupied slot with `--force`
12. **List** shows populated slots after import
13. **Info** shows device details
14. **Error cases**: wrong PIN (check retry count warning), wrong mgm key, no YubiKey
    connected, unsupported algorithm on older firmware
15. **Cross-platform** — test on macOS and Linux (Linux requires `pcscd`)

### Verification with PIV Applications

After importing a key, verify it works with real tools:
- `ssh-keygen -D /usr/lib/opensc-pkcs11.so` (list PIV keys as SSH public keys)
- `pkcs11-tool --list-objects` (via OpenSC)
- `yubico-piv-tool -a status` (verify slot contents)

## Implementation Order

1. Add `yubikey` dependency and feature gate to `Cargo.toml`
2. Create `src/tool/command/yubikey_cmd.rs` with command structs and `process()` skeleton
3. Implement `yubikey info` and `yubikey list` (simplest, good for verifying crate works)
4. Implement `yubikey import ecc` — P-256 first, with cert generation, overwrite protection
5. Add Ed25519 support to `yubikey import ecc`
6. Register command in `mod.rs` and test manually
7. Implement `yubikey import rsa` (2048-bit, then 3072/4096)
8. Implement `yubikey cert` (standalone certificate generation)
9. Add P-384 and X25519 support
10. Add tab completion in `main.rs`
11. Hardware testing across YubiKey models

## Dependencies Summary

| Crate | Version | Feature | Purpose |
|-------|---------|---------|---------|
| `yubikey` | 0.8 | `untested` | YubiKey PIV operations (key import, device info) |

The `yubikey` crate internally depends on `pcsc` for smart card access. On Linux, this
requires `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (Fedora/RHEL) and the
`pcscd` daemon running. On macOS, PC/SC is built into the system (CryptoTokenKit). On
Windows, the WinSCard API is used.
