# Plan: `asf-import` Command — Apple Security Framework Keychain Import

## Context

MSecret derives deterministic cryptographic keys from a master secret. Currently, derived ECC keys can be exported as PEM/hex/SSH formats, but there is no way to load them directly into the macOS Keychain. This plan adds an `asf-import` command that takes a derived P-256 private key and imports it into the Keychain via Apple Security Framework APIs, optionally with biometric (Touch ID) access control.

This enables workflows like deriving an SSH key at a specific keypath and making it available to macOS system tools (e.g., `ssh-keychain(8)`) while minimizing exposure of raw key material.

## Feasibility Assessment

**Verdict: Feasible.** The Rust `security-framework` crate (v3.x) provides safe wrappers around the core APIs we need:

- `SecKey::from_data(KeyType, &CFData)` — create a SecKey from raw key bytes
- `ItemAddOptions` — add keys to the keychain with labels
- `SecAccessControl` — create biometric access policies
- `Location::DataProtectionKeychain` / `DefaultFileKeychain` — keychain target selection

For biometric access control, `ItemAddOptions` does not expose `kSecAttrAccessControl`, so we will need to drop to the `security-framework-sys` level to construct the `SecItemAdd` dictionary manually for the `-t bio` path.

**Key format:** Apple expects EC private keys in X9.63 format: `04 || X(32) || Y(32) || K(32)` = 97 bytes for P-256. The existing `p256` crate (already a dependency) provides everything needed for this conversion.

## Command Design

```
asf-import ecc <CURVE> -l <LABEL> [-t bio|none] [--dry-run]
```

- `CURVE`: `prime256v1` / `p256` / `p-256` / `nistp256` / `secp256r1` (initially P-256 only)
- `-l, --label`: Keychain item label (required)
- `-t, --access-type`: `none` (default) or `bio` (Touch ID)
- `--dry-run`: Show what would be imported without doing it

Example:
```
$ msecretctl
> secret zero
Imported DCUUx9UhnhJErcndchjMsZ
/> cd /special/key/path/1
/special/key/path/1> asf-import ecc prime256v1 -l ssh -t bio
```

## Feature Gating

Dual gate: Cargo feature `asf` + `target_os = "macos"`. Not included in default features since it is macOS-only and would break cross-platform builds.

All ASF code uses: `#[cfg(all(target_os = "macos", feature = "asf"))]`

## Files to Modify

### 1. `Cargo.toml` — Add dependencies and feature

Add optional dependencies:
```toml
security-framework = { version = "3", optional = true }
security-framework-sys = { version = "2.16", optional = true }
core-foundation = { version = "0.10", optional = true }
```

Add feature:
```toml
"asf" = ["security-framework", "security-framework-sys", "core-foundation"]
```

### 2. `src/tool/command/asf.rs` — New file

Contains:
- `AsfAccessType` enum (`None`, `Bio`) with `clap::ValueEnum`
- `CommandAsfImport` enum with `Ecc` variant (clap Subcommand)
- `normalize_curve_name()` — accept P-256 aliases, return canonical name
- `p256_to_x963_private()` — convert `p256::SecretKey` to 97-byte X9.63 format
- `import_to_keychain()` — create `SecKey` from X9.63 data and store in keychain
  - **`-t none` path**: Use high-level `ItemAddOptions` with `DefaultFileKeychain`
  - **`-t bio` path**: Construct raw `CFMutableDictionary` with `SecAccessControl` flags, call `SecItemAdd` via FFI, use `DataProtectionKeychain`
- `process()` method following the standard `<T: AsMut<S>, S: ToolState, W: Write>` pattern
- Zeroize X9.63 buffer after use (using existing `zeroize` dep)
- Unit tests for format conversion and curve name normalization

### 3. `src/tool/command/mod.rs` — Register command

- Add conditional `mod asf;` and `pub use asf::*;`
- Add `AsfImport(CommandAsfImport)` variant to `Command` enum (feature-gated)
- Add match arm in `Command::process()`

### 4. `src/tool/main.rs` — Tab completion

Extend `is_ecc_curve_position()` to also match `asf-import ecc` context so curve names auto-complete.

## Key Implementation Details

### X9.63 Format Conversion

```rust
fn p256_to_x963_private(secret_key: &p256::SecretKey) -> Vec<u8> {
    let public_key = secret_key.public_key();
    let uncompressed = public_key.to_encoded_point(false); // 04 || X || Y (65 bytes)
    let mut x963 = uncompressed.as_bytes().to_vec();
    x963.extend_from_slice(secret_key.to_bytes().as_slice()); // append K (32 bytes)
    x963 // 97 bytes total
}
```

### Keychain Import (non-biometric)

```rust
let cf_data = CFData::from_buffer(&x963_data);
let sec_key = SecKey::from_data(KeyType::ec(), &cf_data)?;
let mut opts = ItemAddOptions::new(ItemAddValue::Ref(AddRef::Key(sec_key)));
opts.set_label(&label);
opts.set_location(Location::DefaultFileKeychain);
opts.add()?;
```

### Keychain Import (biometric)

Build raw CFDictionary with `kSecAttrAccessControl` and `kSecUseDataProtectionKeychain`, call `SecItemAdd` via `security-framework-sys`.

### Error Handling

Map common OSStatus codes to actionable messages:
- `-25299` (errSecDuplicateItem): "Key already exists, delete or use different label"
- `-34018` (errSecMissingEntitlement): "Biometric requires code-signed binary"
- Other codes: generic "SecItemAdd failed with status {code}"

## Code Signing Note

- `-t none`: No code signing required, works out of the box
- `-t bio`: Requires the binary to be code-signed with `keychain-access-groups` entitlement. Ad-hoc signing works for development: `codesign --entitlements entitlements.plist -s - target/debug/msecretctl`

The command should include a clear error message when biometric import fails due to missing entitlements.

## Verification

1. `cargo build --features asf` — compiles on macOS
2. `cargo build` (without `asf`) — compiles on all platforms, no regressions
3. `cargo test --features asf` — unit tests for format conversion and curve normalization pass
4. Manual REPL test (each line is a separate REPL command inside `msecretctl`):
   ```
   $ msecretctl
   > secret zero
   Imported DCUUx9UhnhJErcndchjMsZ
   /> cd /test
   /test> asf-import ecc p256 -l msecret-test -t none
   ```
   Verify key appears in Keychain Access.app
5. Manual REPL test for biometric (requires code-signed binary):
   ```
   /test> asf-import ecc p256 -l msecret-test-bio -t bio
   ```
   Verify Touch ID prompt and key appears in keychain
6. Verify `--dry-run` prints key info without importing
7. Verify duplicate label produces clear error message
