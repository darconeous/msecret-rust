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

use crate::prelude_internal::*;

use digest::{FixedOutputReset, Output, OutputSizeUser};
use ed25519_dalek::{Signer, Verifier};
use elliptic_curve::bigint::Encoding;

#[cfg(feature = "openssl")]
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{self, EcGroupRef, EcKey},
    pkey::{Private, Public},
};
use signature::DigestSigner;

/// Some diffe-helman methods take an actual digest object for the
/// prehash instead of taking the actual hash. This is a wrapper
/// around a hash that will look enough like a digest object to
/// finalize properly. The only method that does anything is `finalize()`.
#[derive(Clone, Copy, Debug)]
struct FakeDigest<'a>(&'a [u8]);

impl<'a> OutputSizeUser for FakeDigest<'a> {
    type OutputSize = typenum::consts::U64;
}

impl<'a> Digest for FakeDigest<'a> {
    fn new() -> Self {
        unreachable!()
    }

    fn new_with_prefix(_data: impl AsRef<[u8]>) -> Self {
        unreachable!()
    }

    fn update(&mut self, _data: impl AsRef<[u8]>) {
        unreachable!()
    }

    fn chain_update(self, _data: impl AsRef<[u8]>) -> Self {
        unreachable!()
    }

    fn finalize(self) -> Output<Self> {
        *Output::<Self>::from_slice(self.0)
    }

    fn finalize_into(self, _out: &mut Output<Self>) {
        unreachable!()
    }

    fn finalize_reset(&mut self) -> Output<Self> {
        unreachable!()
    }

    fn finalize_into_reset(&mut self, _out: &mut Output<Self>)
    where
        Self: FixedOutputReset,
    {
        unreachable!()
    }

    fn reset(&mut self) {
        unreachable!()
    }

    fn output_size() -> usize {
        64
    }

    fn digest(_data: impl AsRef<[u8]>) -> Output<Self> {
        unreachable!()
    }
}

/// Elliptic Curve Operations.
///
/// ## V1 Algorithm ##
///
/// The underlying secret is first mutated with the salt `"\x00EC_v1"`. Then
/// an integer is derived with the group order used as the maximum value.
/// The resulting value is used as the private EC key.
pub trait Ecc {
    /// Derives a [`::ed25519_dalek::SecretKey`] from the underlying secret.
    fn extract_ed25519_private(&self) -> Result<ed25519_dalek::SigningKey>;

    /// Derives a [`::ed25519_dalek::VerifyingKey`] from the underlying secret.
    fn extract_ed25519_public(&self) -> Result<ed25519_dalek::VerifyingKey> {
        Ok((&self.extract_ed25519_private()?).into())
    }

    fn sign_ed25519(&self, msg: &[u8]) -> Result<[u8; 64]> {
        Ok(self.extract_ed25519_private()?.sign(msg).to_bytes())
    }

    fn verify_ed25519(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        self.extract_ed25519_public()?
            .verify(msg, &ed25519_dalek::Signature::from_slice(sig)?)?;
        Ok(())
    }

    fn sign_ed25519ph(&self, prehash: &[u8], context: Option<&[u8]>) -> Result<[u8; 64]> {
        ensure!(
            prehash.len() == 64,
            "`prehash` must have a length of 64 bytes"
        );

        Ok(self
            .extract_ed25519_private()?
            .with_context(context.unwrap_or(&[]))?
            .try_sign_digest(FakeDigest(prehash))?
            .to_bytes())
    }

    fn verify_ed25519ph(&self, prehash: &[u8], context: Option<&[u8]>, sig: &[u8]) -> Result<()> {
        ensure!(
            prehash.len() == 64,
            "`prehash` must have a length of 64 bytes"
        );

        self.extract_ed25519_public()?.verify_prehashed(
            FakeDigest(prehash),
            context,
            &ed25519_dalek::Signature::from_slice(sig)?,
        )?;
        Ok(())
    }

    /// Derives a [`::x25519_dalek::StaticSecret`] from the underlying secret.
    fn extract_x25519_private(&self) -> Result<[u8; 32]>;

    /// Derives a [`::x25519_dalek::PublicKey`] from the underlying secret.
    fn extract_x25519_public(&self) -> Result<[u8; 32]> {
        let static_secret = x25519_dalek::StaticSecret::from(self.extract_x25519_private()?);
        let public_key = x25519_dalek::PublicKey::from(&static_secret);
        Ok(public_key.to_bytes())
    }

    /// Performs Diffe Helman key exchange with the x25519 key derived from this secret
    /// and the given `public` key.
    fn diffe_helman_x25519(&self, public: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(
            x25519_dalek::StaticSecret::from(self.extract_x25519_private()?)
                .diffie_hellman(&x25519_dalek::PublicKey::from(*public))
                .to_bytes(),
        )
    }

    /// Derives a [`::p256::SecretKey`] from the underlying secret,
    /// using the "MSecret EC v1" algorithm.
    fn extract_ec_v1_private_p256(&self) -> Result<p256::SecretKey>;

    /// Derives a [`::p256::PublicKey`] from the underlying secret,
    /// using the "MSecret EC v1" algorithm.
    fn extract_ec_v1_public_p256(&self) -> Result<p256::PublicKey> {
        Ok(self.extract_ec_v1_private_p256()?.public_key())
    }

    /// Derives a [`::k256::SecretKey`] from the underlying secret,
    /// using the "MSecret EC v1" algorithm.
    fn extract_ec_v1_private_secp256k1(&self) -> Result<k256::SecretKey>;

    /// Derives a [`::k256::PublicKey`] from the underlying secret,
    /// using the "MSecret EC v1" algorithm.
    fn extract_ec_v1_public_secp256k1(&self) -> Result<k256::PublicKey> {
        Ok(self.extract_ec_v1_private_secp256k1()?.public_key())
    }

    /// Derives a [`::openssl::ec::EcKey<Private>`] in `group` from the underlying secret,
    /// using the "MSecret EC v1" algorithm.
    #[cfg(feature = "openssl")]
    fn extract_ec_v1_private_openssl(&self, group: &EcGroupRef) -> Result<EcKey<Private>>;

    /// Derives a [`::openssl::ec::EcKey<Public>`] in `group` from the underlying secret,
    /// using the "MSecret EC v1" algorithm.
    #[cfg(feature = "openssl")]
    fn extract_ec_v1_public_openssl(&self, group: &EcGroupRef) -> Result<EcKey<Public>> {
        let private = self.extract_ec_v1_private_openssl(group)?;

        Ok(ec::EcKey::from_public_key(group, private.public_key())?)
    }

    /// Returns the raw output from the ECDH operation with a [`p256::PublicKey`] from the peer.
    ///
    /// The output from this operation should not be used directly, it should
    /// first be passed to separate key derivation function, or at least a hash.
    fn diffe_helman_ec_v1_p256(&self, public: &p256::PublicKey) -> Result<[u8; 32]> {
        let private = self.extract_ec_v1_private_p256()?;
        let output = p256::ecdh::diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
        let mut ret = [0u8; 32];
        ret.copy_from_slice(output.raw_secret_bytes().as_slice());

        Ok(ret)
    }
}

impl Ecc for Secret {
    fn extract_ed25519_private(&self) -> Result<ed25519_dalek::SigningKey> {
        const SALT: &[u8] = b"\x00ED25519";

        let mut key_bytes = [0u8; 32];

        self.subsecret_from_salt(SALT)?
            .extract_bytes_into(&mut key_bytes)?;

        Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
    }

    fn extract_x25519_private(&self) -> Result<[u8; 32]> {
        const SALT: &[u8] = b"\x00X25519";

        let mut key_bytes = [0u8; 32];

        self.subsecret_from_salt(SALT)?
            .extract_bytes_into(&mut key_bytes[..])?;

        // We could perform the following masking operations
        // defined on RFC 7748, Page 8, but these operations
        // are always performed by the x25519 function.
        // Since the X25519 function does these masks anyway,
        // we skip them here in order to avoid fingerprinting.
        // key_bytes[0] &= 248;
        // key_bytes[31] &= 127;
        // key_bytes[31] |= 64;

        Ok(key_bytes)
    }

    fn extract_ec_v1_private_p256(&self) -> Result<p256::SecretKey> {
        use elliptic_curve::Curve;
        const SALT: &[u8] = b"\x00EC_v1";

        let order = p256::NistP256::ORDER.to_be_bytes();

        let key_bytes = self
            .subsecret_from_salt(SALT)?
            .extract_int_to_be_vec(&order)?;

        Ok(p256::SecretKey::from_slice(&key_bytes)?)
    }

    fn extract_ec_v1_private_secp256k1(&self) -> Result<k256::SecretKey> {
        use elliptic_curve::Curve;
        const SALT: &[u8] = b"\x00EC_v1";

        let order = k256::Secp256k1::ORDER.to_be_bytes();

        let key_bytes = self
            .subsecret_from_salt(SALT)?
            .extract_int_to_be_vec(&order)?;

        Ok(k256::SecretKey::from_slice(&key_bytes)?)
    }

    #[cfg(feature = "openssl")]
    fn extract_ec_v1_private_openssl(&self, group: &EcGroupRef) -> Result<EcKey<Private>> {
        const SALT: &[u8] = b"\x00EC_v1";
        let mut ctx = BigNumContext::new_secure()?;
        let mut order = BigNum::new()?;
        group.order(&mut order, &mut ctx)?;

        let private_key = self.subsecret_from_salt(SALT)?.extract_big_num(&order)?;

        let mut public_key = ec::EcPoint::new(group)?;

        public_key.mul_generator(group, &private_key, &ctx)?;

        let key = ec::EcKey::from_private_components(group, &private_key, &public_key)?;

        key.check_key()?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "openssl")]
    use openssl::nid::Nid;
    use sha2::Sha512;

    #[test]
    fn test_ed25519() {
        let secret = Secret::ZERO;
        let msg = b"Hello, World!";
        let sig = secret.sign_ed25519(msg).unwrap();

        secret.verify_ed25519(msg, &sig).unwrap();
        assert!(secret.verify_ed25519(b"Goodbye!", &sig).is_err());
    }

    #[test]
    fn test_ed25519ph() {
        let secret = Secret::ZERO;
        let msg = b"Hello, World!";
        let prehash = Sha512::digest(msg);
        let sig = secret.sign_ed25519ph(prehash.as_slice(), None).unwrap();

        secret
            .verify_ed25519ph(prehash.as_slice(), None, &sig)
            .unwrap();
    }

    #[test]
    fn test_ed25519ph_context() {
        let secret = Secret::ZERO;
        let msg = b"Hello, World!";
        let prehash = Sha512::digest(msg);
        let context = Some(b"MyContext".as_slice());
        let sig = secret.sign_ed25519ph(prehash.as_slice(), context).unwrap();

        secret
            .verify_ed25519ph(prehash.as_slice(), context, &sig)
            .unwrap();
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_ecdh_x25519() {
        let secretA = Secret::ZERO.subsecret_from_label("secretA").unwrap();
        let secretB = Secret::ZERO.subsecret_from_label("secretB").unwrap();

        let sessionAB = secretA
            .diffe_helman_x25519(&secretB.extract_x25519_public().unwrap())
            .unwrap();
        let sessionBA = secretB
            .diffe_helman_x25519(&secretA.extract_x25519_public().unwrap())
            .unwrap();

        assert_eq!(sessionAB, sessionBA);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_ecdh_p256() {
        let secretA = Secret::ZERO.subsecret_from_label("secretA").unwrap();
        let secretB = Secret::ZERO.subsecret_from_label("secretB").unwrap();

        let sessionAB = secretA
            .diffe_helman_ec_v1_p256(&secretB.extract_ec_v1_public_p256().unwrap())
            .unwrap();
        let sessionBA = secretB
            .diffe_helman_ec_v1_p256(&secretA.extract_ec_v1_public_p256().unwrap())
            .unwrap();

        assert_eq!(sessionAB, sessionBA);
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_extract_ec_v1_private() {
        let group = ec::EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let ec = Secret::ZERO.extract_ec_v1_private_openssl(&group).unwrap();
        let pem = ec.private_key_to_pem().unwrap();
        let pem_str = std::str::from_utf8(&pem).unwrap();

        println!("{pem_str}");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(pem_str.as_bytes());
        assert_eq!(
            hex::encode(hasher.finalize()),
            "50916d8e3ac8229c94f1507d75b74d23be6ce791bcd1a3ee5d55c8ecc321d9f3".to_string()
        );
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_extract_ec_v1_public() {
        let group = ec::EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let ec = Secret::ZERO.extract_ec_v1_public_openssl(&group).unwrap();
        let pem = ec.public_key_to_pem().unwrap();
        let pem_str = std::str::from_utf8(&pem).unwrap();
        println!("{pem_str}");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(pem_str.as_bytes());
        assert_eq!(
            hex::encode(hasher.finalize()),
            "fa66fb153fe8426a52e85122ea02fa5a06eb905f9fa350d8a448486383733696".to_string()
        );
    }
}
