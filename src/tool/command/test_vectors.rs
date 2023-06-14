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

use ::rsa::traits::{PrivateKeyParts, PublicKeyParts};

#[derive(Debug, clap::Args)]
pub struct CommandTestVectors {}

impl CommandTestVectors {
    pub fn process<T: AsMut<S>, S: ToolState, W: Write>(
        &self,
        mut _tool_state: T,
        out: &mut W,
    ) -> Result<(), Error> {
        let secret_list = &[
            Secret::ZERO,
            Secret::ZERO.subsecret_from_label("1")?,
            Secret::ZERO.subsecret_from_label("2")?,
            Secret::ZERO.subsecret_from_label("721")?,
        ];

        writeln!(out, "MSecret Test Vectors")?;
        writeln!(out, "====================")?;
        writeln!(out)?;

        writeln!(out, "MSecret Bytes")?;
        writeln!(out, "-------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            for i in [4, 8, 16, 32, 64] {
                let x = hex::encode(secret.extract_bytes(i)?);
                writeln!(out, " * {i}-Bytes: `{x}`")?;
            }
            writeln!(out)?;
        }

        writeln!(out, "MSecret Integers")?;
        writeln!(out, "----------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            for i in [4, 8, 16, 32] {
                let x = secret.extract_u64(2u64.pow(i))?;
                writeln!(out, " * Max 2^{i}: {x}")?;
            }

            for i in [64u32, 128, 256, 512, 1024] {
                use num_traits::Pow;
                let x = secret.extract_big_uint(&(BigUint::from(2usize).pow(i)))?;
                writeln!(out, " * Max 2^{i}: {x}")?;
            }
            writeln!(out)?;
        }

        writeln!(out, "MSecret Primes")?;
        writeln!(out, "--------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            for i in [4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048] {
                let x = secret.extract_prime_v1_big_uint(i)?;
                writeln!(out, " * Max (2^{i}-1): {x}")?;
            }

            writeln!(out)?;
        }

        writeln!(out, "RSA Keys")?;
        writeln!(out, "--------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            for i in [512, 1024, 2048] {
                let x = secret.extract_rsa_v1_private(i)?;
                writeln!(out, " * {i} Bit")?;
                writeln!(out, "   * e: {}", x.e())?;
                writeln!(out, "   * p: {}", x.primes()[0])?;
                writeln!(out, "   * q: {}", x.primes()[1])?;
                writeln!(out, "   * n: {}", x.n())?;
                writeln!(out, "   * d: {}", x.d())?;
            }

            writeln!(out)?;
        }

        writeln!(out, "MSecret Ed25519")?;
        writeln!(out, "---------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            let x = hex::encode(secret.extract_ed25519_private()?.to_bytes().as_slice());
            writeln!(out, " * Priv: `{x}`")?;
            let x = hex::encode(secret.extract_ed25519_public()?.as_bytes());
            writeln!(out, " * Pub:  `{x}`")?;

            writeln!(out)?;
        }

        writeln!(out, "MSecret X25519")?;
        writeln!(out, "--------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            let x = hex::encode(secret.extract_x25519_private()?.as_slice());
            writeln!(out, " * Priv: `{x}`")?;
            let x = hex::encode(secret.extract_x25519_public()?.as_slice());
            writeln!(out, " * Pub:  `{x}`")?;

            writeln!(out)?;
        }

        writeln!(out, "MSecret P-256")?;
        writeln!(out, "-------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            let x = hex::encode(secret.extract_ec_v1_private_p256()?.to_bytes().as_slice());
            writeln!(out, " * Priv: `{x}`")?;
            let public = secret.extract_ec_v1_public_p256()?;
            let x = hex::encode(public.to_sec1_bytes());
            writeln!(out, " * Pub:  `{x}`")?;

            writeln!(out)?;
        }

        writeln!(out, "MSecret SECP256K1")?;
        writeln!(out, "-----------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            let x = hex::encode(
                secret
                    .extract_ec_v1_private_secp256k1()?
                    .to_bytes()
                    .as_slice(),
            );
            writeln!(out, " * Priv: `{x}`")?;
            let public = secret.extract_ec_v1_public_secp256k1()?;
            let x = hex::encode(public.to_sec1_bytes());
            writeln!(out, " * Pub:  `{x}`")?;

            writeln!(out)?;
        }

        writeln!(out, "MSecret Bitcoin")?;
        writeln!(out, "---------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            let x = hex::encode(secret.extract_bitcoin_v1_private_key()?);
            writeln!(out, " * Priv : {x}")?;

            let x = hex::encode(secret.extract_bitcoin_v1_public_key()?);
            writeln!(out, " * Pub  : {x}")?;

            let x = secret.extract_bitcoin_v1_address_b58()?;
            writeln!(out, " * Addr : {x}")?;

            let x = secret.extract_bitcoin_v1_wif_b58()?;
            writeln!(out, " * WIF  : {x}")?;

            writeln!(out)?;
        }

        writeln!(out, "MSecret Passwords")?;
        writeln!(out, "-----------------")?;
        writeln!(out)?;

        for secret in secret_list {
            writeln!(out, "Secret: `{secret}`")?;
            writeln!(out)?;

            let x = secret.extract_password_v1()?;
            writeln!(out, " * v1: `{x}`")?;
            let x = secret.extract_password_v2()?;
            writeln!(out, " * v2: `{x}`")?;

            writeln!(out)?;
        }

        writeln!(out, "MSecret Derivation from Passphrase")?;
        writeln!(out, "----------------------------------")?;
        writeln!(out)?;

        for passphrase in ["Hello, World!", "Secure Passphrase"] {
            writeln!(out, "Passphrase: {passphrase:?}")?;
            writeln!(out, "Secret: {}", Secret::from_passphrase(passphrase))?;
            writeln!(out)?;
        }

        Ok(())
    }
}
