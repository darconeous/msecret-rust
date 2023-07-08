MSecret — Experimental Key Derivation Utility
=============================================

[![crates.io][crate-image]][crate-link]
[![Build Status][build-image]][build-link]
[![Documentation][doc-image]][doc-link]
[![dependency status][deps-image]][deps-link]
![MSRV][msrv-image]

-------

This project includes both:

1.  A [specification][MSECRET] (with [test vectors][VECTORS]) for deterministically deriving
    various types of data (bytes, integers, primes, etc.) and
    cryptographic keys (RSA, ECC, etc.) from a symmetric master secret.
2.  A reference implementation written in Rust, including a [helpful
    command-line utility](#command-line-tool) and [library][doc-link].

[MSECRET]: doc/MSECRET.md
[VECTORS]: doc/TEST_VECTORS.md

## ⚠️ WARNINGS ⚠️ ##

Use this project at your own risk. As with anything experimental
and cryptographic, there are some caveats to understand before using
this project:

### ⚠️ BEHAVIOR SUBJECT TO CHANGE ⚠️ ###

The MSecret specification and the included reference implementation
should be considered EXPERIMENTAL AND SUBJECT TO CHANGE until the
specification is declared final. **Any changes to the derivation
specification will change the output of the resulting keys.** Also,
any mistakes in the implementation of the specification may also lead
to incorrect results.

If you need to ensure that any keys you derive from the included
reference tool will always derive to the same key in later revisions,
you should avoid using this software until the specification and test
vectors are finalized.

### ⚠️ NOT AUDITED ⚠️ ###

Neither the reference source code nor the test vectors have been
audited for correctness.

### ⚠️ SIDE-CHANNEL ATTACKS ⚠️ ###

The reference source code has not been hardened against side-channel
attacks.

## How it works ##

In MSecret, secrets are defined to be 256-bits long. The
[MSecret specification][MSECRET] defines methods for how various
types of cryptographic keys (RSA, EC, etc) and other values (integers,
pseudo-random byte strings, etc.) can be deterministically derived
from a 256-bit secret.

In addition to deriving cryptographic keys and other values, also
defined is a way to derive other 256-bit secrets from a "label". These
derivations may be chained together to form a "keypath", allowing for
a hierarchical structure of derived keys. This allows for complex
forms of domain separation.

### Defined Pseudo-random Derivations ###

1.  Other 256-bit symmetric secrets, via a label/keypath
2.  Byte strings of arbitrary length
3.  Integers with a maximum value
4.  Prime numbers of a given bit length
5.  RSA public/private keys of a given bit length
6.  ECC public/private keys for arbitrary curves, including Ed25519
    and X25519
7.  Various styles of passwords
8.  Bitcoin addresses and associated private keys

### Secret Management ###

Secrets can be generated randomly or derived from a passphrase using
[argon2id][]. Secrets can also be split up into an arbitrary number of
"shares", from which a subset can be used to recover the secret
(m-of-n secret sharing).

[argon2id]: https://en.wikipedia.org/wiki/Argon2

### Keypaths ###

Keypaths are strings of labels separated by slashes ("`/`"), making
them appear like the path in a file system: i.e.
"`/A/1/CA/com.example/2023-06-23`". The key derivations are performed
hierarchically, so that the secret at the path "`/A/1`" could be
exported and later used to derive the secret at
"`CA/com.example/2023-06-23`".

Chains of the same label are supported via a special notation. The
following keypaths are all equivalent:

*   `/x/x/x/x`
*   `/x@4`
*   `/x/x@3`
*   `/x@2/x@2`

## Command-Line Tool ##

To install the command-line tool `msecretctl`, first make sure that your
rust development environment is installed and up-to-date. To install
from scratch, read the instructions [here](https://www.rust-lang.org/tools/install).
To update an existing installation, use rustup:

```shell
$ rustup update
```

Then you can grab the latest version of `msecretctl`:

```shell
$ cargo install msecret
```

You should now be able to use the `msecretctl` tool.

### Usage Example ###

The included reference implementation includes a command-line utility
called `msecretctl` which can be used to derive various secrets. It has
an interactive mode which can be entered by simply running it.

Here is an example of using the tool to generate a new root secret and
split it into 5 shares (where any three could reconstruct it):

```
$ cargo build --release
$ target/release/msecretctl

> secret generate
Created XvvjqeUihQncbhsVQBtToB

/> secret share 3 5
ARhqDQyLeN1K92xHxYkWhVHbGRsjLdduhPDPT6L2FsroNfT
ErtgQEvsXKA9TgYRnjqE2s4NFhwbPd4e5YVwDU3X6cCDoZ9
NvBfSVbkqmN37jxa8689S8htmPXnxaqvdH13FkaDLaAdWb3
Sf1GNofy4vvij3Z4uziDuxuc54ZSGiwY9MQ9fJQcWdkLSEi
aL1RKsJPN9ZsSPhifiJGz5PSB35HRTy7kNitYYHw8LAEUHA
```

We then go on to derive two private keys for X.509 certificates:

```
/> cd /A/1/CA/com.example/2023-06-23

/A/1/CA/com.example/2023-06-23> ecc private prime256v1
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP9sNI1FKOOT0Pm56bpbXAP/aQiCu+nlXus1OcZYlt4xoAoGCCqGSM49
AwEHoUQDQgAE1YGpnNePZH5u6apTZpUP7/9W1xaJ8x5JNxqPxyh8gf6B2xStFB7q
UIVkSB54IZGHuuQKkYwfCjT69zDGVRwt7A==
-----END EC PRIVATE KEY-----

/A/1/CA/com.example/2023-06-23> cd ../../net.example.com/2023-06-23

/A/1/CA/net.example/2022-00-21> ecc private prime256v1
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBDh1+5kobZT/IuuLx3KyLsaFqSF7WDVAC91/Ih9LzpeoAoGCCqGSM49
AwEHoUQDQgAEU3lNhlWMkmVN6MEbWFIbCRH9uE4I5bxt+WSHn/vUpk9weJ/LJ4vt
q9Wc+L1K/7QKbkJ2T0S+0PsNfQWWN2aDog==
-----END EC PRIVATE KEY-----

/A/1/CA/net.example/2022-00-21> exit

$
```

If we need to recover these private keys later, we can use
any three of the above shares to recover the key:

```
$ target/release/msecretctl

> secret recover
Enter Share: Sf1GNofy4vvij3Z4uziDuxuc54ZSGiwY9MQ9fJQcWdkLSEi
Enter Share: ARhqDQyLeN1K92xHxYkWhVHbGRsjLdduhPDPT6L2FsroNfT
Enter Share: NvBfSVbkqmN37jxa8689S8htmPXnxaqvdH13FkaDLaAdWb3
Enter Share:
Imported XvvjqeUihQncbhsVQBtToB

/> cd /A/1/CA/com.example/2023-06-23

/A/1/CA/com.example/2023-06-23> ecc private prime256v1
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP9sNI1FKOOT0Pm56bpbXAP/aQiCu+nlXus1OcZYlt4xoAoGCCqGSM49
AwEHoUQDQgAE1YGpnNePZH5u6apTZpUP7/9W1xaJ8x5JNxqPxyh8gf6B2xStFB7q
UIVkSB54IZGHuuQKkYwfCjT69zDGVRwt7A==
-----END EC PRIVATE KEY-----

/A/1/CA/com.example/2023-06-23>
```

You could also export/share just the key at `/A/1`...

```
/A/1/CA/com.example/2023-06-23> cd /A/1

/A/1> secret id
EhK8TqdqrJ6xBaxEYx2mmb

/A/1> secret share 2 3 -f words
light-conan-flame--valid-input-poncho--bronze-falcon-jacob--piano-frame-popular--ticket-sharp-smoke--burger-status-father--cobra-ship-marion--water-shake-alien--except-private-fax
saint-queen-video--elite-martin-amber--canal-ferrari-jamaica--escape-soprano-dinner--honey-food-infant--paper-george-jumbo--cotton-vision-madonna--radio-rodent-episode--rainbow-citizen-ego
sonata-tropic-mask--voice-edgar-cool--cotton-reptile-alien--meaning-carol-common--dynasty-joker-bamboo--poker-educate-random--lion-nova-demand--smile-escort-kilo--basket-ocean-fax

/A/1> q

$
```

...and then derive the ECC keys from that:

```
$ target/release/msecretctl

> secret recover
Enter Share: sonata-tropic-mask--voice-edgar-cool--cotton-reptile-alien--meaning-carol-common--dynasty-joker-bamboo--poker-educate-random--lion-nova-demand--smile-escort-kilo--basket-ocean-fax
Enter Share: light-conan-flame--valid-input-poncho--bronze-falcon-jacob--piano-frame-popular--ticket-sharp-smoke--burger-status-father--cobra-ship-marion--water-shake-alien--except-private-fax
Enter Share:
Imported EhK8TqdqrJ6xBaxEYx2mmb

/> cd CA/com.example/2023-06-23

/CA/com.example/2023-06-23> ecc private prime256v1
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP9sNI1FKOOT0Pm56bpbXAP/aQiCu+nlXus1OcZYlt4xoAoGCCqGSM49
AwEHoUQDQgAE1YGpnNePZH5u6apTZpUP7/9W1xaJ8x5JNxqPxyh8gf6B2xStFB7q
UIVkSB54IZGHuuQKkYwfCjT69zDGVRwt7A==
-----END EC PRIVATE KEY-----

/CA/com.example/2023-06-23>
```

## Future Work

* Finalize specification
* Smart card support with permissions
* Keypath maps
* Additional asymmetric key formats

# License

Apache 2.0; see [`LICENSE`](LICENSE) for details.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/msecret
[crate-link]: https://crates.io/crates/msecret
[doc-image]: https://docs.rs/msecret/badge.svg
[doc-link]: https://docs.rs/msecret
[build-image]: https://github.com/darconeous/msecret-rust/workflows/CI/badge.svg
[build-link]: https://github.com/darconeous/msecret-rust/actions?query=workflow%3ACI+branch%3Amain
[msrv-image]: https://img.shields.io/badge/rustc-1.70+-blue.svg
[deps-image]: https://deps.rs/crate/msecret/0.1.2/status.svg
[deps-link]: https://deps.rs/crate/msecret/

[//]: # (links)
