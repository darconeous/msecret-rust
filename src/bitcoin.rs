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

pub trait ExtractBitcoinV1 {
    /// Extracts a bitcoin private key. Note that this is simply
    /// the raw bytes of the `secp256k1` key derived for this secret.
    fn extract_bitcoin_v1_private_key(&self) -> Result<Vec<u8>>;

    fn extract_bitcoin_v1_public_key(&self) -> Result<Vec<u8>>;

    fn extract_bitcoin_v1_wif(&self) -> Result<Vec<u8>> {
        let mut key = self.extract_bitcoin_v1_private_key()?;
        key.insert(0, 0x80);
        key.push(0x01); // Use compressed public keys
        append_hash(&mut key);
        Ok(key)
    }

    fn extract_bitcoin_v1_wif_b58(&self) -> Result<String> {
        Ok(bs58::encode(self.extract_bitcoin_v1_wif()?).into_string())
    }

    fn extract_bitcoin_v1_address(&self) -> Result<Vec<u8>> {
        let mut hasher = Sha256::default();
        hasher.update(&self.extract_bitcoin_v1_public_key()?);
        let tmp = hasher.finalize();

        let mut hasher = Ripemd160::default();
        hasher.update(tmp);
        let mut addr = hasher.finalize().to_vec();

        addr.insert(0, 0x00);

        append_hash(&mut addr);

        Ok(addr)
    }

    fn extract_bitcoin_v1_address_b58(&self) -> Result<String> {
        Ok(bs58::encode(self.extract_bitcoin_v1_address()?).into_string())
    }
}

fn append_hash(key: &mut Vec<u8>) {
    let mut hasher = Sha256::default();
    hasher.update(&key);
    let tmp = hasher.finalize();
    let mut hasher = Sha256::default();
    hasher.update(tmp);
    let hash = hasher.finalize();

    key.extend_from_slice(&hash[0..4])
}

impl ExtractBitcoinV1 for Secret {
    fn extract_bitcoin_v1_private_key(&self) -> Result<Vec<u8>> {
        let key = self.extract_ec_v1_private_secp256k1()?.to_bytes().to_vec();

        assert_eq!(key.len(), 32);

        Ok(key)
    }

    fn extract_bitcoin_v1_public_key(&self) -> Result<Vec<u8>> {
        use elliptic_curve::group::GroupEncoding;
        let key = self.extract_ec_v1_public_secp256k1()?;
        let bytes = key.as_affine().to_bytes().to_vec();

        assert_eq!(bytes.len(), 33);

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "openssl")]
    trait ExtractBitcoinV1OpenSSL: Derivable {
        fn extract_bitcoin_v1_openssl_private_key(&self) -> Result<Vec<u8>> {
            let group =
                openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1).unwrap();
            let key = self
                .extract_ec_v1_private_openssl(&group)?
                .private_key()
                .to_vec_padded(32)?;

            assert_eq!(key.len(), 32);

            Ok(key)
        }

        fn extract_bitcoin_v1_openssl_public_key(&self) -> Result<Vec<u8>> {
            let mut ctx = openssl::bn::BigNumContext::new_secure()?;
            let group =
                openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1).unwrap();
            let ec_v1 = self.extract_ec_v1_public_openssl(&group)?;

            let key = ec_v1.public_key();

            let mut x = openssl::bn::BigNum::new()?;
            let mut y = openssl::bn::BigNum::new()?;

            key.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;

            let mut key = x.to_vec_padded(32)?;
            key.insert(0, if y.is_bit_set(0) { 0x03 } else { 0x02 });

            assert_eq!(key.len(), 33);

            Ok(key)
        }
    }

    #[cfg(feature = "openssl")]
    impl ExtractBitcoinV1OpenSSL for Secret {}

    /// Test for making sure that the OpenSSL version
    /// and the pure-rust version are functionally equivalent.
    #[test]
    #[cfg(feature = "openssl")]
    fn test_check_openssl_equivalence() {
        for i in 0..1000 {
            let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
            assert_eq!(
                secret.extract_bitcoin_v1_openssl_public_key().unwrap(),
                secret.extract_bitcoin_v1_public_key().unwrap()
            );
            assert_eq!(
                secret.extract_bitcoin_v1_openssl_private_key().unwrap(),
                secret.extract_bitcoin_v1_private_key().unwrap()
            );
        }
    }

    #[test]
    fn test_extract_bitcoin_v1() {
        let key = Secret::ZERO.extract_bitcoin_v1_wif_b58().unwrap();
        println!("bitcoin private key: {key}");
        assert_eq!(&key, "KzH5bXKEwJ7ryigXESxBtbB1mbcbt1czfDbNxQFYSPXV1yJkfRd5");
    }

    #[test]
    fn test_public_bitcoin_v1() {
        let key = Secret::ZERO.extract_bitcoin_v1_address_b58().unwrap();
        println!("bitcoin address: {key}");
        assert_eq!(&key, "16d5NbPiZMUks5fLNof98ddpF2Cpk3Xi4m");
    }

    #[test]
    fn test_bitcoin_shorttest() {
        let mut hash = Sha256::default();

        for i in 0..1000 {
            let secret = Secret::ZERO.subsecret_from_label(&i.to_string()).unwrap();
            let wif = secret.extract_bitcoin_v1_wif_b58().unwrap();
            hash.update(wif.as_bytes());
            let addr = secret.extract_bitcoin_v1_address_b58().unwrap();
            hash.update(addr.as_bytes());
        }

        let hash = hex::encode(hash.finalize().as_slice());
        assert_eq!(
            hash,
            "c62878adeb602926b626fa72c3fa0ebcbc9c6886605cae8881ac74e0cea24714"
        );
    }
}
