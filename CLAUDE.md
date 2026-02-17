# MSecret - CLAUDE.md

## Project Overview

MSecret is an experimental key derivation utility and formal specification written in pure Rust. It deterministically derives cryptographic material (keys, passwords, primes, etc.) from a 256-bit symmetric master secret using a hierarchical "keypath" structure for domain separation.

The project has two targets:
- **Library** (`msecret`): Trait-based Rust library for programmatic use
- **Binary** (`msecretctl`): Interactive REPL CLI tool

## Architecture

### Core Design Pattern

The `Secret` struct (256-bit key material) implements a hierarchy of derivation traits, all unified under the `Derivable` supertrait:

- `MutateWith` - transform a secret with a salt/label (HKDF-based)
- `SubsecretFrom` - hierarchical derivation (keypath navigation)
- `ExtractBytes` - pseudo-random byte strings
- `ExtractInteger` - uniform random integers up to a max
- `ExtractPassword` - human-readable passwords (V1: ~91 bits, V2: ~60 bits phone-friendly)
- `ExtractPrimeV1` - prime numbers (Miller-Rabin + Baillie-PSW)
- `ExtractRsaV1` - RSA key pairs (2048-4096 bit, E=65537)
- `Ecc` - ECC keys (P-256, secp256k1, Ed25519, X25519)
- `ExtractBitcoinV1` - Bitcoin private keys, WIF, and addresses

### Module Layout

```
src/
├── lib.rs          - Library root; defines Derivable supertrait and SecretId
├── secret.rs       - Secret struct; random generation, Argon2id passphrase derivation
├── tool_state.rs   - ToolState trait for secret management; KeyMap for tracking derivatives
├── bytes.rs        - ExtractBytes (HKDF-Expand based)
├── integer.rs      - ExtractInteger
├── prime.rs        - ExtractPrimeV1
├── rsa.rs          - ExtractRsaV1
├── ec.rs           - Ecc trait (P-256, secp256k1, Ed25519, X25519)
├── bitcoin.rs      - ExtractBitcoinV1
├── password.rs     - ExtractPassword (V1 and V2)
├── tests.rs        - Integration tests against test vectors
└── tool/
    ├── main.rs                 - CLI entry; ToolArgs (clap); rustyline REPL
    ├── bin_format.rs           - Binary format support (base58, hex, base64, mnemonic)
    ├── tests.rs                - Tool integration tests
    └── command/
        ├── mod.rs              - Command enum routing all CLI commands
        ├── secret.rs           - generate, zero, id, passphrase, export, save, share, recover, load
        ├── ls_cd.rs            - Filesystem-like keypath navigation
        ├── bytes.rs            - bytes command
        ├── int.rs              - int command
        ├── prime.rs            - prime command
        ├── rsa.rs              - rsa command
        ├── ecc.rs              - ecc command
        ├── btc.rs              - btc command
        ├── password.rs         - password command
        └── test_vectors.rs     - test-vectors command
```

### Features

- `default` = `["openssl", "share", "bin"]`
- `share` - M-of-N secret sharing via Shamir's scheme (`gf256`, `crc`)
- `bin` - CLI tool (`clap`, `rustyline`, `rpassword`, `shellwords`, `mnemonic`)
- `openssl` - OpenSSL-backed ECC support
- `longtest` - Extended test suite

## Key Algorithms and Cryptography

- **Derivation**: HKDF (SHA-256) is the primary derivation primitive
- **Passphrase-to-secret**: Argon2id
- **RSA**: Deterministic prime generation, E=65537
- **ECC curves**: P-256, secp256k1, Ed25519, X25519
- **Bitcoin**: RIPEMD-160 + SHA-256, Base58Check, WIF encoding
- **Secret sharing**: Shamir's Secret Sharing over GF(256)
- **Memory safety**: `zeroize` used for secure clearing of key material

## Build and Test

```bash
# Standard build
cargo build

# Build CLI tool (included in default features)
cargo build --release

# Run tests
cargo test

# Run extended tests
cargo test --features longtest
```

## Documentation

- `README.md` - Overview, installation, usage examples
- `doc/MSECRET.md` - Formal specification of all derivation algorithms
- `doc/TEST_VECTORS.md` - Reference test vectors for all derivation types
- Word lists for password generation: `contrib/wordy-password/`

## Status

This project is **experimental**. The specification and derived values are not yet considered stable.
