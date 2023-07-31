MSecret v0.1 Specification
==========================

This document outlines mechanisms for deriving an assortment of
cryptographic secrets from a symmetric 256-bit master secret,
including a mechanism for deriving other master secrets to facilitate
domain separation.

There isn't anything terribly clever going on here, but if you want
repeatability you need to spell out all of the details explicitly.
That's what this document is about.

## Copyright and License

Copyright (C) 2023 Robert Quattlebaum. All rights reserved.

This use of this document is hereby granted under the terms of the
Creative Commons International Attribution 4.0 Public License, as
published by Creative Commons.

*  <https://creativecommons.org/licenses/by/4.0/>

This work is provided as-is. Unless otherwise provided in writing, the
authors make no representations or warranties of any kind concerning
this work, express, implied, statutory or otherwise, including without
limitation warranties of title, merchantability, fitness for a
particular purpose, non infringement, or the absence of latent or
other defects, accuracy, or the present or absence of errors, whether
or not discoverable, all to the greatest extent permissible under
applicable law.

## Disclaimer

This document is an informal work-in-progress, may
contain errors, and is subject to change at any time.

## Secrets

In this document, a "Secret" refers specifically to a 256-bit
master secret from which the rest of the algorithms described in
this specification may be performed on. It is defined to be created
in one of the following ways:

1. Randomly from a cryptographic random number generator.
2. From a passphrase or other low-entropy source using Argon2.
3. From a high-entropy source using `HKDF-Extract<SHA256>`.

The value of a Secret is intended to be suitable for direct use
as the PRK to HKDF-Expand.

## Identifying Secrets

A secret can be identified by its *secret-id*. The *secret-id* can be
calculated from the secret as follows:

* Calculate the `HMAC<SHA256>` of the secret using the key `"\x00SecretId"`.
  (That is, the ASCII string `SecretId` with a zero byte prepended to it)
* Truncate the resulting value to first 16 bytes.
* Base58-encode the resulting 16 byte value.

For example, the secret-id for the all-zeros secret is `DCUUx9UhnhJErcndchjMsZ`.

## Mutating Secrets

In order to facilitate domain separation, Secrets may be mutated
with a salt or "label" using `HKDF-Extract<SHA256>`, where the
`IKM` is the original Secret and the `salt` is supplied as a
parameter of the mutation. The result is the new derived secret.

Note that `HKDF-Extract<SHA256>(IKM,salt)` is defined to be the
same as `HMAC<SHA256>(msg:IKM,key:salt)`.

## Deriving Pseudo-Random Byte Strings

* Input
  * `secret`: Secret
  * `len`: Number of Bytes
* Output
  * An array of `len` pseudorandom bytes.

Pseudorandom bytes may be derived from a Secret using
HKDF-Expand with `info` set to the byte string `"\x00Bytes_v1"`,
where `\x00` is interpreted as a zero byte.

Domain separation is achieved by mutating the Secret using a label
or salt value.

## Deriving Pseudo-Random Integers

* Input
    * `secret`: Secret
    * `max`: Maximum integer value
* Output
    * A pseudo-random integer between 0 and `max`.

The algorithm internally uses big-endian representations.

Let's start out with the value `0x001337FF` as `max`.

First, we transform `max` into a big-endian array of bytes.
So `max` becomes `[00 13 37 FF]`.

We then strip all the leading zero bytes. This makes
`max` become `[13 37 FF]`.

Next we calculate a value named `enclosing_mask`, which is
calculated from the first (most-significant) byte in `max`:

    fn enclosing_mask_u8(mut x: u8) -> u8 {
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x
    }

    let enclosing_mask = enclosing_mask_u8(max[0]);

Because the first byte in `max` has the value 0x13,
`enclosing_mask` is set to the value 0x1f.

We then start our loop. In our calculation loop, we do the
following:

1. Mutate `secret` to be the result of `HKDF-Extract<SHA256>` using the
   trimmed bytes in `max` as the salt and the previous value of
   `secret` as the `IKM`.
2. Derive the same number of bytes in `max` (using the procedure outlined
   above) to the byte array `out`.
3. Apply `enclosing_mask` to the first byte of `out`.
   (i.e.: `out[0] &= enclosing_mask`).
4. Perform a lexicographical comparison between `out` and `max`. If `out`
   comes after `max`, then go to step 1.

At this point `out` contains our derived integer in big-endian byte form,
and may then be converted to whatever other sort of integer representation
you might need.

## Deriving Pseudo-Random Primes

* Input
    * `secret`: Secret
    * `bit_length`: the number of bits that this prime should have.
* Output
    * A pseudo-random prime between 0 and `max`.

1. Ensure that `bit_length` is greater than or equal to `4`.
2. The underlying secret is first mutated with the salt `"\x00Prime_v1"`.
3. Calculate the integer `max` so that `max = (1<<bit_length)-1`.
4. Derive a pseudo-random integer between 0 and `max` using the algorithm
   described above and assign that value to `out`.
5. Set the least significant bit on `out`, ensuring that it is odd.
6. Set the most significant bit on `out`.
7. If `bit_length` is larger than 32, set the next most significant bit
   on `out`.

We then enter the following loop:

1. Check to see if `out` is prime, according to the primality
   test outlined below.
2. If `out` is not prime, increment `out` by two and
   jump to step 1 in this loop.

At this point `out` contains our random prime.

### Primality Test ###

A given integer is considered "prime" if it passes the
The [FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
C.3.1 Miller-Rabin test with an iteration count of 20.
The chances that the resulting number is not prime is
$2^{-40}$, or roughly one in a trillion.

If this is not considered a suitable level of confidence,
the iteration count MAY be increased or the [Baillie-PSW test](https://en.wikipedia.org/wiki/Baillie–PSW_primality_test)
MAY be used instead.

## Deriving RSA Private Keys

* **Input**
    * `secret`: Secret
    * `mod_length`: the number of bits in the modulus.
* **Output**
  * Two primes, (`P` and `Q`) that are suitable for use in
    an RSA private key with an exponent of 65537. All other
    parameters from an RSA key can be computed from these
    values.

The procedure for calculating a suitable prime number is designed
to mutate the `secret` in-place. In practice a copy of `secret`
is made so that the original value is not lost. Then the following
procedure is considered `calc_candidate_prime(bit_length)`:

1. `secret` is mutated in-place with the salt `"\x00RSA_v1"`. This
   provides some amount of domain separation.
2. Calculate a `candidate_prime` from the working secret using
   the prime derivation algorithm defined above and the given `bit_length`.
3. Usability check: If `E` (65537) is a factor of `(candidate_prime-1)`, goto step 1.
4. Use `candidate_prime` as our prime.

We can then use `calc_candidate_prime(bit_length)` to calculate two
suitable primes:

* `prime1_bits` is defined as `(mod_length + 1) / 2`.
* `prime1` is calculated as `calc_candidate_prime(prime1_bits)`
* `prime2` is calculated as `calc_candidate_prime(mod_length - prime1_bits)`

If `prime2` is equal to `prime1`, then do the following:

* If `mod_length >= 256`, return an error, since this should basically never happen.
* If `mod_length < 256`, recalculate `prime2` until it does not. Note that this
  will only happen when generating "toy" keys that offer no security.

By convention, the larger prime is considered `P` and the smaller prime is
considered `Q`. These primes may then be used to calculate the other
components of the RSA key as described in other literature.

The exponent of the key is always assumed be 65537.

### RSA Security Analysis

The algorithm is largely based on the implementation
from OpenSSL's `RSA_generate_key()` method, as seen
[here](https://opensource.apple.com/source/OpenSSL097/OpenSSL097-16/openssl/crypto/rsa/rsa_gen.c).

This is a straightforward algorithm that avoids doing the
sorts of checks that are extremely unlikely to ever be
triggered assuming modern (>2048 bits) key lengths are
used, such as:

  * Determining that P and Q differ by at least 2^100
  * Ensuring that neither (P-1) nor (Q-1) have of lots of small factors

When generating large keys, it is far more likely that
the source keying material has been compromised than
randomly generating a large key that happens to not also
satisfy those sorts of constraints. So the only check we
make against P and Q is ensuring that E is not a factor
of (P-1) or (Q-1), which is required for RSA to work at
all.

As a result, the security of RSA keys generated by this
algorithm for smaller key sizes (<=1024 bits) *may* be suspect.
However, you shouldn't be using 1024-bit keys anyway.

## Deriving ECC Private Keys

* Input
    * `secret`: Secret
    * `order`: The prime order of the curve.
* Output
    * `out`: The private key scalar for the given prime order.

> **NOTE**: This process MUST NOT be used to generate the private keys
>           for the following: `Ed25519`, `X25519`, `Ed448`, or `X448`.
>           The private key values for these are calculated differently.

Steps:

1. The underlying secret is first mutated with the salt `"\x00EC_v1"`.
2. Derive a pseudo-random integer between 0 and `order` using the algorithm
   described above and assign that value to `out`.
3. Assert that `out` is not zero. (This is, of course, extremely unlikely)

The value `out` may now be used as the scalar for the private key
on the given curve.

## Deriving `Ed25519`, `X25519`, `Ed448`, or `X448` private keys

* Input
    * `secret`: Secret
* Output
    * `out`: The private key bytes

Steps:

1. The underlying secret is first mutated with a salt dependent on
   the type of key desired:
   * Ed25519: `"\x00ED25519"`
   * X25519: `"\x00X25519"`
   * Ed448: `"\x00ED448"`
   * X448: `"\x00X448"`
2. Derive a byte string `out` with the appropriate number of bytes
   for the given system:
    * Ed25519/X25519: 32
    * Ed448/X448: 56

The byte array `out` may now be used as the private key.

## Deriving Passwords

TODO: Writeme!

## Deriving Secrets from Passphrases

Secrets are derived from passphrases using [ARGON2][]
with the following parameters:

 * Version: 1.3
 * Variant: ARGON2ID
 * Iterations: 3
 * Memory Size: 262,144kiB (256MiB)
 * Lanes: 4
 * Output Tag Length: 32 Bytes
 * Salt: ASCII String "MSecret_Passphrase_v1"

The output tag is used directly as the Secret.

[ARGON2]: https://www.rfc-editor.org/rfc/rfc9106.html

## Splitting Secrets into Shares

First, a CRC-8 is calculated over the secret and appended
to the secret. The specific CRC that is used is
[CRC_8_BLUETOOTH](https://docs.rs/crc-catalog/latest/crc_catalog/constant.CRC_8_BLUETOOTH.html).
The resulting value is 33 bytes long.

This secret is then split into shares using the algorithm outlined
in the section below, each share being 34 bytes long.

For each share, the CRC-8 is calculated (same as above) and also
appended. The resulting shares are each 35 bytes long. The shares
are then encoded as desired (Base58 is a common encoding).

When decoding, the CRC of each individual share should be verified.
Once combined, the CRC of the final secret should also be verified.

The CRCs help to detect typos for individual shares and also
to help determine that the final secret is valid with some small
degree of confidence. This is for convenience only. Successful
decoding is no substitute for verifying that the resulting secret
matches the expected secret-id.

### `SSS-GF(256)`

The specific SSS-FG(256) algorithm being employed is the same
algorithm being used by the following independent projects:

* https://docs.rs/gf256/latest/gf256/shamir/index.html
* https://github.com/jcushman/libgfshare

#### See also

* [draft-mcgrew-tss-03](https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03):
  Not being used here, but mentioning it for later consideration.

## Test Vectors

See the [test vector document](TEST_VECTORS.md).

## References

TODO: Writeme!
