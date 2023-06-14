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

#[cfg(feature = "openssl")]
use openssl::{
    bn::{BigNum, BigNumContext},
    pkey::{Private, Public},
    rsa::Rsa as OpenSslRsa,
};

use ::rsa::{RsaPrivateKey, RsaPublicKey};
use num_bigint::{BigUint, ModInverse};
use zeroize::Zeroizing;

/// RSA Operations.
///
/// ## V1 Algorithm ##
///
/// The algorithm for calculating RSA keys is very straightforward:
/// We calculate two suitable primes (P and Q, calculated using the
/// procedure outlined below) of the correct size and use those primes
/// to derive all the other parameters of the key.
///
/// In the V1 algorithm, E is always the value 65537.
///
/// ### Finding Suitable Primes ##
///
/// First, a copy of the underlying secret is made so that it can
/// be mutated. This copy is called the "working secret". Whenever a
/// suitable prime is needed by the algorithm, the following procedure
/// is used:
///
/// 1. The working secret is mutated in-place with the salt `"\x00RSA_v1"`.
/// 2. Calculate `candidate_prime` from the working secret using
///    the "MSecret Prime V1" algorithm.
/// 3. If E is a factor of (`candidate_prime`-1), goto step 1.
/// 4. Use `candidate_prime` as our prime.
///
/// ### Additional Background ###
///
/// The algorithm is largely based on the implementation
/// from OpenSSL's `RSA_generate_key()` method, as seen here:
///
/// https://opensource.apple.com/source/OpenSSL097/OpenSSL097-16/openssl/crypto/rsa/rsa_gen.c
///
/// This is a straightforward algorithm that avoids doing the
/// sorts of checks that are extremely unlikely to ever be
/// triggered assuming modern (>2048 bits) key lengths are
/// used, such as:
///
///   * determining that P and Q differ by at least 2^100
///   * ensuring that (P-1) and (Q-1) have no small factors.
///
/// When generating large keys, it is far more likely that
/// the source keying material has been compromised than
/// randomly generating a large key that happens to not also
/// satisfy those sorts of constraints. As a result, the only
/// check we make against P and Q is ensuring that E is not
/// a factor of (P-1) or (Q-1).
///
/// As a result, the security of RSA keys generated by this
/// algorithm for key sizes smaller than 1024 bits is suspect.
/// However, you shouldn't be using 1024-bit keys anyway.
///
pub trait ExtractRsaV1 {
    /// Derives a [`RsaPrivateKey`] of `mod_length` from the underlying secret,
    /// using the "MSecret RSA v1" algorithm.
    ///
    /// This uses the simplified v1 algorithm, which should produce
    /// good results for large key sizes. The security of the resulting
    /// key will be compromised if `mod_length` is less than 1024.
    ///
    /// The value `e` is always assumed to be 65537.
    fn extract_rsa_v1_private(&self, mod_length: u16) -> Result<RsaPrivateKey>;

    /// Derives a [`RsaPublicKey`] of `mod_length` from the underlying secret,
    /// using the "MSecret RSA v1" algorithm.
    ///
    /// This uses the simplified v1 algorithm, which should produce
    /// good results for large key sizes. The security of the resulting
    /// key will be compromised if `mod_length` is less than 1024.
    ///
    /// The value `e` is always assumed to be 65537.
    fn extract_rsa_v1_public(&self, mod_length: u16) -> Result<RsaPublicKey> {
        Ok(self.extract_rsa_v1_private(mod_length)?.to_public_key())
    }

    /// Derives an [`openssl::rsa::Rsa<Private>`] of `mod_length` from the underlying secret,
    /// using the "MSecret RSA v1" algorithm.
    #[cfg(feature = "openssl")]
    fn extract_rsa_v1_private_openssl(&self, mod_length: u16) -> Result<OpenSslRsa<Private>>;

    /// Derives an [`openssl::rsa::Rsa<Public>`] of `mod_length` from the underlying secret,
    /// using the "MSecret RSA v1" algorithm.
    #[cfg(feature = "openssl")]
    fn extract_rsa_v1_public_openssl(&self, mod_length: u16) -> Result<OpenSslRsa<Public>> {
        let private = self.extract_rsa_v1_private_openssl(mod_length)?;
        let e = private.e().to_owned()?;
        let n = private.n().to_owned()?;

        Ok(OpenSslRsa::<Public>::from_public_components(n, e)?)
    }

    /// Decrypts the given ciphertext with OAEP+SHA256 padding using the RSA private key derived
    /// from the underlying secret.
    fn decrypt_rsa_v1_oaep_sha256(
        &self,
        mod_length: u16,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;

    /// Encrypts the given plaintext with OAEP+SHA256 padding using the RSA public key derived
    /// from the underlying secret.
    fn encrypt_rsa_v1_oaep_sha256(
        &self,
        mod_length: u16,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// Decrypts the given ciphertext WITHOUT ANY PADDING using the RSA private key derived from
    /// the underlying secret.
    ///
    /// **No padding is used.** Padding MUST be handled by the application!
    fn decrypt_rsa_v1_raw(
        &self,
        mod_length: u16,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;

    /// Encrypts the given plaintext WITHOUT ANY PADDING using the RSA private key derived from
    /// the underlying secret.
    ///
    /// **No padding is used.** Padding MUST be handled by the application!
    fn encrypt_rsa_v1_raw(
        &self,
        mod_length: u16,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    fn sign_rsa_v1_pkcs1_v15_prehash(
        &self,
        mod_length: u16,
        digest: &[u8],
        signature: &mut [u8],
    ) -> Result<usize>;

    fn verify_rsa_v1_pkcs1_v15_prehash(
        &self,
        mod_length: u16,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()>;

    fn sign_rsa_v1_pkcs1_v15_sha256(
        &self,
        mod_length: u16,
        message: &[u8],
        signature: &mut [u8],
    ) -> Result<usize>;

    fn verify_rsa_v1_pkcs1_v15_sha256(
        &self,
        mod_length: u16,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

impl ExtractRsaV1 for Secret {
    fn extract_rsa_v1_private(&self, mod_length: u16) -> Result<RsaPrivateKey> {
        use num_integer::Integer;
        use num_traits::*;
        const SALT: &[u8] = b"\x00RSA_v1";

        ensure!(mod_length > 7, "Invalid mod length {mod_length}");

        let mut msecret = Zeroizing::new(self.clone());
        let one = BigUint::one();
        let e = BigUint::from(65537u32);

        // This is our subroutine which calculates
        // a suitable P or Q value, taking into account
        // the value of E.
        let mut calc_suitable_prime = |bits| -> Result<BigUint> {
            loop {
                msecret.mutate_with_salt(SALT)?;

                let mut prime = msecret.extract_prime_v1_big_uint(bits)?;

                // Verify that the prime is suitable.
                // If it isn't, we try again.
                prime -= &one;
                if (prime.gcd(&e) - &one).is_zero() {
                    // No common factors with `e`, so we choose this prime.
                    prime += &one;
                    break Ok(prime);
                }
            }
        };

        // Calculate 'p'
        let bitsp = (mod_length + 1) / 2;
        let mut p = calc_suitable_prime(bitsp)?;

        // Calculate 'q'
        let bitsq = mod_length - bitsp;
        let mut q = loop {
            let q = calc_suitable_prime(bitsq)?;
            if mod_length >= 256 {
                // For larger mod lengths, P and Q are
                // not expected to end up being equal,
                // so we fail hard in that case.
                ensure!(p != q, "P must not equal Q");
            }
            if p == q {
                // Otherwise, P and Q might
                // end up being equal. Here we account
                // for that case and recalculate.
                // Note that this only happens when
                // calculating toy parameters.
                continue;
            }
            break q;
        };

        // P should be the larger of the two, by convention.
        if p.lt(&q) {
            std::mem::swap(&mut p, &mut q);
        }

        // Calculate N
        let n = &p * &q;

        // Calculate D
        let d = (&e)
            .mod_inverse(&n - &p - &q + &one)
            .unwrap()
            .to_biguint()
            .unwrap();

        let key = RsaPrivateKey::from_components(n, e, d, vec![p, q])?;

        key.validate()?;

        Ok(key)
    }

    #[cfg(feature = "openssl")]
    fn extract_rsa_v1_private_openssl(&self, mod_length: u16) -> Result<OpenSslRsa<Private>> {
        const SALT: &[u8] = b"\x00RSA_v1";

        ensure!(mod_length > 7, "Invalid mod length {mod_length}");

        let mut msecret = self.clone();
        let mut ctx = BigNumContext::new_secure()?;
        let one = BigNum::from_u32(1)?;

        let e = BigNum::from_u32(65537)?;

        // Temporary working "registers"
        let mut r0 = BigNum::new_secure()?;
        let mut r1 = BigNum::new_secure()?;
        let mut r2 = BigNum::new_secure()?;

        // This is our subroutine which calculates
        // a suitable P or Q value, taking into account
        // the value of E.
        let mut calc_suitable_prime = |bits| -> Result<BigNum> {
            loop {
                msecret.mutate_with_salt(SALT)?;

                let mut prime = msecret.extract_prime_v1_bignum(bits)?;

                // Verify that the prime is suitable.
                // If it isn't, we try again.
                prime.sub_word(1)?;
                r1.gcd(&prime, &e, &mut ctx)?;
                r1.sub_word(1)?;
                if r1.num_bits() == 0 {
                    // No common factors with `e`, so we choose this prime.
                    prime.add_word(1)?;
                    break Ok(prime);
                }
            }
        };

        // Calculate 'p'
        let bitsp = (mod_length + 1) / 2;
        let mut p = calc_suitable_prime(bitsp)?;

        // Calculate 'q'
        let bitsq = mod_length - bitsp;
        let mut q = loop {
            let q = calc_suitable_prime(bitsq)?;
            if mod_length >= 256 {
                // For larger mod lengths, P and Q are
                // not expected to end up being equal,
                // so we fail hard in that case.
                ensure!(p != q, "P must not equal Q");
            }
            if p == q {
                // Otherwise, P and Q might
                // end up being equal. Here we account
                // for that case and recalculate.
                // Note that this only happens when
                // calculating toy parameters.
                continue;
            }
            break q;
        };

        assert_ne!(p, q);

        // P should be the larger of the two, by convention.
        if p < q {
            std::mem::swap(&mut p, &mut q);
        }

        // Calculate N
        let mut n = BigNum::new_secure()?;
        n.checked_mul(&p, &q, &mut ctx)?;

        // Calculate D
        // n = p*q
        // (p-1)(q-1) = p*q - p - q + 1
        // (p-1)(q-1) = n - p - q + 1
        // So we just subtract `p` and `q` from `n` and add one.
        let mut d = BigNum::new_secure()?;
        // BN_sub(r0, rsa->n, rsa->p);
        r0.checked_sub(&n, &p)?;
        // BN_sub(r1, r0, rsa->q);
        r1.checked_sub(&r0, &q)?;
        // BN_add(r0, r1, BN_value_one());
        r0.checked_add(&r1, &one)?;
        // BN_mod_inverse(rsa->d, rsa->e, r0, ctx);
        d.mod_inverse(&e, &r0, &mut ctx)?;

        // Calculate DMP1
        let mut dmp1 = BigNum::new_secure()?;
        // BN_sub(r1, rsa->p, BN_value_one());
        r1.checked_sub(&p, &one)?;
        // BN_mod(rsa->dmp1,rsa->d,r1,ctx);
        dmp1.nnmod(&d, &r1, &mut ctx)?;

        // Calculate DMQ1
        let mut dmq1 = BigNum::new_secure()?;
        // BN_sub(r2, rsa->q, BN_value_one());
        r2.checked_sub(&q, &one)?;
        // BN_mod(rsa->dmq1,rsa->d,r2,ctx);
        dmq1.nnmod(&d, &r2, &mut ctx)?;

        // Calculate IQMP
        let mut iqmp = BigNum::new_secure()?;
        iqmp.mod_inverse(&q, &p, &mut ctx)?;

        let key = OpenSslRsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)?;

        key.check_key()?;

        Ok(key)
    }

    fn decrypt_rsa_v1_oaep_sha256(
        &self,
        mod_length: u16,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize> {
        let rsa = self.extract_rsa_v1_private(mod_length)?;

        let padding = ::rsa::Oaep::new::<sha2::Sha256>();
        let result = Zeroizing::new(rsa.decrypt_blinded(
            &mut ::rsa::rand_core::OsRng,
            padding,
            ciphertext,
        )?);

        if result.len() > plaintext.len() {
            bail!("plaintext not large enough");
        }

        plaintext[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    /// Performs RSA encryption using OAEP.
    fn encrypt_rsa_v1_oaep_sha256(
        &self,
        mod_length: u16,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize> {
        let rsa = self.extract_rsa_v1_public(mod_length)?;

        let padding = ::rsa::Oaep::new::<sha2::Sha256>();
        let result = rsa.encrypt(&mut ::rsa::rand_core::OsRng, padding, plaintext)?;

        if result.len() > ciphertext.len() {
            bail!("ciphertext not large enough");
        }
        ciphertext[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    #[cfg(feature = "openssl")]
    fn decrypt_rsa_v1_raw(
        &self,
        mod_length: u16,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize> {
        let rsa = self.extract_rsa_v1_private_openssl(mod_length)?;
        Ok(rsa.private_decrypt(ciphertext, plaintext, openssl::rsa::Padding::NONE)?)
    }

    #[cfg(not(feature = "openssl"))]
    fn decrypt_rsa_v1_raw(
        &self,
        mod_length: u16,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize> {
        use ::rsa::traits::PrivateKeyParts;
        use ::rsa::traits::PublicKeyParts;

        let rsa = self.extract_rsa_v1_private(mod_length)?;
        let m = Zeroizing::new(BigUint::from_bytes_be(ciphertext));

        // TODO: Perform blinding
        let result = m.modpow(rsa.d(), rsa.n()).to_bytes_be();

        if result.len() > plaintext.len() {
            bail!("ciphertext not large enough");
        }
        plaintext[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    /// Performs raw RSA encryption. No padding is assumed.
    /// Padding MUST be handled by the application!
    fn encrypt_rsa_v1_raw(
        &self,
        mod_length: u16,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize> {
        use ::rsa::traits::PublicKeyParts;

        // Equivalent code from OpenSSL
        //
        // let rsa = self.extract_rsa_v1_public_openssl(mod_length)?;
        // Ok(rsa.public_encrypt(plaintext, ciphertext, openssl::rsa::Padding::NONE)?)

        let rsa = self.extract_rsa_v1_public(mod_length)?;
        let m = Zeroizing::new(BigUint::from_bytes_be(plaintext));
        let result = m.modpow(rsa.e(), rsa.n()).to_bytes_be();

        if result.len() > ciphertext.len() {
            bail!("ciphertext not large enough");
        }
        ciphertext[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    fn sign_rsa_v1_pkcs1_v15_prehash(
        &self,
        mod_length: u16,
        digest: &[u8],
        signature: &mut [u8],
    ) -> Result<usize> {
        use ::rsa::signature::hazmat::PrehashSigner;
        use ::rsa::signature::SignatureEncoding;
        let rsa = self.extract_rsa_v1_private(mod_length)?;
        let key = ::rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa);

        let result = key.sign_prehash(digest)?.to_vec();

        if result.len() > signature.len() {
            bail!("signature not large enough");
        }

        signature[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    fn verify_rsa_v1_pkcs1_v15_prehash(
        &self,
        mod_length: u16,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use ::rsa::signature::hazmat::PrehashVerifier;
        let rsa = self.extract_rsa_v1_public(mod_length)?;
        let key = ::rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa);
        let signature = ::rsa::pkcs1v15::Signature::try_from(signature)?;
        key.verify_prehash(digest, &signature)?;
        Ok(())
    }

    fn sign_rsa_v1_pkcs1_v15_sha256(
        &self,
        mod_length: u16,
        message: &[u8],
        signature: &mut [u8],
    ) -> Result<usize> {
        use ::rsa::signature::SignatureEncoding;
        use ::signature::Signer;
        let rsa = self.extract_rsa_v1_private(mod_length)?;
        let key = ::rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa);

        let result = key.sign(message).to_vec();

        if result.len() > signature.len() {
            bail!("signature not large enough");
        }

        signature[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }

    fn verify_rsa_v1_pkcs1_v15_sha256(
        &self,
        mod_length: u16,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use ::signature::Verifier;
        let rsa = self.extract_rsa_v1_public(mod_length)?;
        let key = ::rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa);
        let signature = ::rsa::pkcs1v15::Signature::try_from(signature)?;
        key.verify(message, &signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_signatures_sha256() {
        let secret = Secret::ZERO;
        let mut sig = vec![0u8; 2048 / 8];
        let msg = b"Hello World";

        let len = secret
            .sign_rsa_v1_pkcs1_v15_sha256(2048, msg, &mut sig)
            .unwrap();
        sig.truncate(len);

        secret
            .verify_rsa_v1_pkcs1_v15_sha256(2048, msg, &sig)
            .unwrap();
    }

    #[test]
    fn test_rsa_signatures_prehash() {
        use digest::Digest;
        let secret = Secret::ZERO;
        let mut sig = vec![0u8; 2048 / 8];
        let msg = b"Hello World";
        let hash = Sha256::digest(msg).to_vec();

        let len = secret
            .sign_rsa_v1_pkcs1_v15_prehash(2048, &hash, &mut sig)
            .unwrap();
        sig.truncate(len);

        secret
            .verify_rsa_v1_pkcs1_v15_prehash(2048, &hash, &sig)
            .unwrap();
    }

    #[test]
    fn test_rsa_signatures_prehash_mix() {
        use digest::Digest;
        let secret = Secret::ZERO;
        let mut sig = vec![0u8; 2048 / 8];
        let msg = b"Hello World";
        let hash = Sha256::digest(msg).to_vec();

        let len = secret
            .sign_rsa_v1_pkcs1_v15_prehash(2048, &hash, &mut sig)
            .unwrap();
        sig.truncate(len);

        secret
            .verify_rsa_v1_pkcs1_v15_sha256(2048, msg, &sig)
            .unwrap();
    }

    #[test]
    fn test_rsa_shorttest() {
        use ::rsa::traits::PrivateKeyParts;
        use ::rsa::traits::PublicKeyParts;
        let mut hash = Sha256::default();

        for m in [18, 128, 256, 512, 1024] {
            for i in 0..1000 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let rsa = secret.extract_rsa_v1_private(m).unwrap();
                hash.update(&rsa.e().to_bytes_be());
                hash.update(&rsa.primes()[0].to_bytes_be());
                hash.update(&rsa.primes()[1].to_bytes_be());
                hash.update(&rsa.n().to_bytes_be());
                hash.update(&rsa.d().to_bytes_be());
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "491905bc4318716c1c84f2d0daa090820231b6a819af2dbcc36f5e3565d0ab93"
        );
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_rsa_shorttest_openssl() {
        let mut hash = Sha256::default();

        for m in [18, 128, 256, 512, 1024] {
            for i in 0..1000 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let rsa = secret.extract_rsa_v1_private_openssl(m).unwrap();
                hash.update(&rsa.e().to_vec());
                hash.update(&rsa.p().unwrap().to_vec());
                hash.update(&rsa.q().unwrap().to_vec());
                hash.update(&rsa.n().to_vec());
                hash.update(&rsa.d().to_vec());
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "491905bc4318716c1c84f2d0daa090820231b6a819af2dbcc36f5e3565d0ab93"
        );
    }

    #[cfg(feature = "longtest")]
    #[test]
    fn test_rsa_longtest() {
        use ::rsa::traits::PrivateKeyParts;
        use ::rsa::traits::PublicKeyParts;
        let mut hash = Sha256::default();

        for m in [18, 128, 256, 512, 1024, 2048] {
            for i in 0..3000 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let rsa = secret.extract_rsa_v1_private(m).unwrap();
                hash.update(&rsa.e().to_bytes_be());
                hash.update(&rsa.primes()[0].to_bytes_be());
                hash.update(&rsa.primes()[1].to_bytes_be());
                hash.update(&rsa.n().to_bytes_be());
                hash.update(&rsa.d().to_bytes_be());
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "70958a58386f7f63b3c4ac5580c5fd7eb3b3813fe10681f09687e2a28e17fa89"
        );
    }

    #[cfg(all(feature = "openssl", feature = "longtest"))]
    #[test]
    fn test_rsa_longtest_openssl() {
        let mut hash = Sha256::default();

        for m in [18, 128, 256, 512, 1024, 2048] {
            for i in 0..3000 {
                let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
                let rsa = secret.extract_rsa_v1_private_openssl(m).unwrap();
                hash.update(&rsa.e().to_vec());
                hash.update(&rsa.p().unwrap().to_vec());
                hash.update(&rsa.q().unwrap().to_vec());
                hash.update(&rsa.n().to_vec());
                hash.update(&rsa.d().to_vec());
            }
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "70958a58386f7f63b3c4ac5580c5fd7eb3b3813fe10681f09687e2a28e17fa89"
        );
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_extract_rsa_v1_private_openssl() {
        let rsa = Secret::ZERO.extract_rsa_v1_private_openssl(2048).unwrap();
        let pem = rsa.private_key_to_pem().unwrap();
        let pem_str = std::str::from_utf8(&pem).unwrap();
        println!("{pem_str}");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(pem_str.as_bytes());
        assert_eq!(
            hex::encode(hasher.finalize()),
            "223e90c069eb29b25fd5d3b4fbf0667dcb480b95fa9f429e8f8631c5eb78e6ae".to_string()
        );
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_extract_rsa_v1_public_openssl() {
        let rsa = Secret::ZERO
            .subsecret_from_path("/MyRSA/")
            .unwrap()
            .extract_rsa_v1_public_openssl(2048)
            .unwrap();
        let pem = rsa.public_key_to_pem().unwrap();
        let pem_str = std::str::from_utf8(&pem).unwrap();
        println!("{pem_str}");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(pem_str.as_bytes());
        assert_eq!(
            hex::encode(hasher.finalize()),
            "810616b37d259cf01c3a379b22ff7a8b36f016e58dbe4cc4c60ab512af35a6b8".to_string()
        );
    }
}
