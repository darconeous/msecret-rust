# YubiKey PIV Integration

This document describes how to use `msecretctl` to import deterministically-derived
keys into a YubiKey PIV slot, and how to verify them using standard PKCS#11 tools.

## Overview

The `yubikey import` command derives a key from the current secret/keypath and loads
it into a PIV slot on an attached YubiKey. Once loaded, the private key never leaves
the hardware — applications interact with it via the PIV PKCS#11 interface.

## Requirements

- YubiKey 5 series (firmware 5.7+ required for Ed25519/X25519/RSA-3072/4096)
- macOS with PC/SC support (built-in)
- Homebrew packages: `yubico-piv-tool` (provides `libykcs11`), `opensc` (provides `pkcs11-tool`)

```bash
brew install yubico-piv-tool opensc
```

## Management Key

The YubiKey PIV management key authenticates administrative operations such as key
import. Its algorithm depends on firmware version:

| Firmware | Default algorithm | Default key (hex) |
|----------|------------------|-------------------|
| ≤ 5.6.x  | 3DES             | `010203040506070801020304050607080102030405060708` |
| ≥ 5.7.0  | AES-192          | `010203040506070801020304050607080102030405060708` |

`msecretctl` automatically selects the correct algorithm for the connected device.
You can override it with `--mgm-key <hex>` or the `MSECRET_YUBIKEY_MGM_KEY` environment
variable. Key length determines algorithm: 16 bytes = AES-128, 24 bytes = AES-192,
32 bytes = AES-256.

> **Important:** Change the management key from the factory default before deploying
> a YubiKey in production. Use `yubico-piv-tool -a set-mgm-key`.

## Importing Keys

### ECC Keys

```
> secret zero
/> yubikey import ecc --slot 9a p256
/> yubikey import ecc --slot 9c ed25519
/> yubikey import ecc --slot 9d x25519 --no-cert
```

Supported curves: `p256`, `p384`, `ed25519`, `x25519`

Notes:
- X25519 is a key-agreement algorithm and cannot self-sign certificates; use `--no-cert`.
- Ed25519 and X25519 require YubiKey firmware 5.7.0 or later.

### RSA Keys

```
/> yubikey import rsa --slot 9c 2048
/> yubikey import rsa --slot 9c 4096
```

Supported sizes: 2048, 3072, 4096 (3072/4096 require firmware 5.7.0+)

### Common Options

| Option | Description |
|--------|-------------|
| `--slot <slot>` | PIV slot: `9a`, `9c`, `9d`, `9e`, `82`–`95` |
| `--mgm-key <hex>` | Management key (overrides env var) |
| `--pin <pin>` | PIN (default: prompted interactively) |
| `--pin-policy <policy>` | `never`, `once`, `always` |
| `--touch-policy <policy>` | `never`, `always`, `cached` |
| `--no-cert` | Skip writing a self-signed certificate to the slot |
| `--force` | Overwrite an existing key |
| `--dry-run` | Show what would be imported without writing to the device |

## PIV Slots

| Slot | Name | PIN required |
|------|------|-------------|
| 9a | PIV Authentication | Once per session |
| 9c | Digital Signature | Every use |
| 9d | Key Management | Once per session |
| 9e | Card Authentication | Never |
| 82–95 | Retired Key Management | Once per session |

## Listing Slot Contents

```
/> yubikey list
YubiKey (serial: 36XXXXXX, firmware: 5.7.4)
  Slot 9a (PIV Authentication): (empty)
  Slot 9c (Digital Signature): Ed25519
  Slot 9d (Key Management): (empty)
  Slot 9e (Card Authentication): (empty)
```

## Verifying a Key with pkcs11-tool

After importing, you can confirm the YubiKey holds the expected key by signing a
message with both the hardware and the software key and comparing the results.
Ed25519 is deterministic: the same key and message always produce the same 64-byte
signature.

### Step 1 — Sign with the YubiKey (via PKCS#11)

```bash
echo -n "hello world" > /tmp/message.bin

pkcs11-tool --module /opt/homebrew/lib/libykcs11.dylib \
  --sign \
  --slot 0 \
  --id 02 \
  --mechanism EDDSA \
  --input-file /tmp/message.bin \
  --output-file /tmp/sig_yk.bin \
  --pin 123456

xxd -p /tmp/sig_yk.bin | tr -d '\n'; echo
```

PKCS#11 object IDs for each slot:

| Slot | `--id` | Notes |
|------|--------|-------|
| 9a   | `01`   | PIV Authentication |
| 9c   | `02`   | Digital Signature |
| 9d   | `03`   | Key Management |
| 9e   | `04`   | Card Authentication |
| 82   | `05`   | Retired Key 1 |
| 83   | `06`   | Retired Key 2 |
| 84   | `07`   | Retired Key 3 |
| 85   | `08`   | Retired Key 4 |
| 86   | `09`   | Retired Key 5 |
| 87   | `0a`   | Retired Key 6 |
| 88   | `0b`   | Retired Key 7 |
| 89   | `0c`   | Retired Key 8 |
| 8a   | `0d`   | Retired Key 9 |
| 8b   | `0e`   | Retired Key 10 |
| 8c   | `0f`   | Retired Key 11 |
| 8d   | `10`   | Retired Key 12 |
| 8e   | `11`   | Retired Key 13 |
| 8f   | `12`   | Retired Key 14 |
| 90   | `13`   | Retired Key 15 |
| 91   | `14`   | Retired Key 16 |
| 92   | `15`   | Retired Key 17 |
| 93   | `16`   | Retired Key 18 |
| 94   | `17`   | Retired Key 19 |
| 95   | `18`   | Retired Key 20 |
| f9   | `19`   | Attestation |

### Step 2 — Sign with msecretctl

Load the same secret and navigate to the same keypath used during import:

```
> secret zero
/> ecc sign ed25519 --file /tmp/message.bin
```

### Step 3 — Compare

Both outputs should be identical 128-character hex strings (64 bytes). If they match,
the YubiKey holds exactly the key derived from your secret at that keypath.

### Listing PKCS#11 Objects

To inspect what keys are visible through the PKCS#11 interface:

```bash
pkcs11-tool --module /opt/homebrew/lib/libykcs11.dylib --list-objects
```

## Key Derivation Path

Keys are derived from the current keypath at the time of import. The keypath is
embedded in the self-signed certificate written to the slot (as the CN), making it
possible to reconstruct which secret/keypath produced a given key:

```
Certificate CN: DCUUx9UhnhJErcndchjMsZ:/some/keypath
```

To re-derive the same key: load the secret with that ID, navigate to that keypath,
and run the same `yubikey import` command.
