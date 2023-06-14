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
use digest::Digest;

#[test]
fn test_secret_zero() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "secret id", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "secret id -f hex", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "62c7c81eb9bdc358596a8486aefc4eb4"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "cd Alice/Bob", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "");
    output.clear();

    ToolArgs::process_line(&mut tool_state, "secret id", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "2gLDGY2o2Fz8Fi72PGbiHu"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "cd Charlie", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "");
    output.clear();

    ToolArgs::process_line(&mut tool_state, "secret id", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "R5Yi54roQfQHdrLaDsyrTV"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "cd ..", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "");
    output.clear();

    ToolArgs::process_line(&mut tool_state, "secret id", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "2gLDGY2o2Fz8Fi72PGbiHu"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "cd ../..", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "");
    output.clear();

    ToolArgs::process_line(&mut tool_state, "secret id", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ls", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "Alice \t[ ]\n");
    output.clear();
}

#[test]
fn test_ecc_ed25519() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc private ed25519 -f hex", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "953e43a53b5e16adc7e97cfd2c1ed579b1e06d268c610ed0b3f9a708e7862838"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc public ed25519 -f hex", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "ff0988597f1bf5914ab5417932dd0b6d41dd2948a5119328b20a0d9d447f3b21"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc private ed25519 -f ssh", &mut output).unwrap();
    let hashstr = hex::encode(sha2::Sha256::digest(output.as_slice()).as_slice());
    assert_eq!(
        hashstr.as_str(),
        "7aaebc59b24d4fdcdf8cbdfd9bde3a8a5fce334f73da640f51abe2d220b587ea"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc public ed25519 -f ssh", &mut output).unwrap();
    let hashstr = hex::encode(sha2::Sha256::digest(output.as_slice()).as_slice());
    assert_eq!(
        hashstr.as_str(),
        "2170b637532549bde74a7b22f5a39324a1521684df26b42f1eb623af6d8bf8bc"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc sign ed25519 01020304", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "14b9bf716c4d8d797aa59be63077be20ddabcf616fbbe33faff3fe598ff78b91695960fb660b71acc04ed5d1ffed47316f1481eaf1749fa30f121cc8a1df3c08"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc verify ed25519 01020304 14b9bf716c4d8d797aa59be63077be20ddabcf616fbbe33faff3fe598ff78b91695960fb660b71acc04ed5d1ffed47316f1481eaf1749fa30f121cc8a1df3c08", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "Ok");
    output.clear();
}

#[test]
fn test_ecc_x25519() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc public x25519 -f hex", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "fe90fb14592ff3349dcc6113bb2f92bfc8ec31a422d377e609deb5fca473ef03"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "ecc private x25519 -f hex", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "a2a5652a4c6285ebfa6aa5bb7895675db394794548162ba6fe9e06e83d0bb91a"
    );
    output.clear();
}

#[test]
fn test_ecc_p256() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    #[cfg(openssl)]
    {
        ToolArgs::process_line(&mut tool_state, "ecc private p256 -f hex", &mut output).unwrap();
        assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            "1adc5e419bef7d8acfc07af9c2f838ff71502b6fc1d18cceaa0c6cd26cc90c2c"
        );
        output.clear();

        ToolArgs::process_line(&mut tool_state, "ecc public p256 -f hex", &mut output).unwrap();
        assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            "02e01ebd7689ff1322c1b72f6826f75896ed6a4ed7ae45c91aa32a73f9618971fd"
        );
        output.clear();
    }
}

#[test]
fn test_rsa() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "rsa public -m 1024", &mut output).unwrap();
    let hashstr = hex::encode(sha2::Sha256::digest(output.as_slice()).as_slice());
    assert_eq!(
        hashstr.as_str(),
        "f3877ae72083aa9414aa1282cdcb58edd9374901d1396ec45d76f75e6fab7709"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "rsa private -m 1024", &mut output).unwrap();
    let hashstr = hex::encode(sha2::Sha256::digest(output.as_slice()).as_slice());
    assert_eq!(
        hashstr.as_str(),
        "d3aefa2e866a62e20507fcbcad2c3c3cd034d05cd312c5ae312b985f96ea27f7"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "rsa encrypt raw -m 1024 --i-know-what-i-am-doing 4b7cecfc87a466197ca1264a791a058c00825f2f220c3937b8cbff68cd8c8f6e7abd42ce3902652da08b6d640aefc606c6aba9fa50e0c638c31dc7857b50ca52bba0fcbb2816586d896c52d2b1eb4dce076df2a35ee4f3eedc5f020973f245b42609c484572dce387cfea5ea0613a552a220b0bf2775cd2ea8b2ca34f678e5e0", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "1f0a5ad30cfc5a3cdf93d230fd8854877f88e928b28bf1786377674b2a7ee3edbb72a60ba67732ea9b04682e9b72c7cef43ca1bdff7604b67ceb056a5936f857589c3f7c29c6bbf7fd8065b6e04f038f24063129f7a682340e7e08ee3ee6e9ecf3a182cb9d5681ab89691a320fe942b8f464b84a1e0743b8568463dcd5c3d0aa"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "rsa decrypt raw -m 1024 --i-know-what-i-am-doing 1f0a5ad30cfc5a3cdf93d230fd8854877f88e928b28bf1786377674b2a7ee3edbb72a60ba67732ea9b04682e9b72c7cef43ca1bdff7604b67ceb056a5936f857589c3f7c29c6bbf7fd8065b6e04f038f24063129f7a682340e7e08ee3ee6e9ecf3a182cb9d5681ab89691a320fe942b8f464b84a1e0743b8568463dcd5c3d0aa", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "4b7cecfc87a466197ca1264a791a058c00825f2f220c3937b8cbff68cd8c8f6e7abd42ce3902652da08b6d640aefc606c6aba9fa50e0c638c31dc7857b50ca52bba0fcbb2816586d896c52d2b1eb4dce076df2a35ee4f3eedc5f020973f245b42609c484572dce387cfea5ea0613a552a220b0bf2775cd2ea8b2ca34f678e5e0"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "rsa decrypt oaep-sha256 -m 1024 6933cf6814309a85ef9822b5a8da54b5639875b8e4375bce9dc57b80c51af8086d5cedca67100248b53ac00f83357fc5b8f26074041c647a6b1a4cb1f5c41b1fe39d6f9d7ecf7fb6515ef52951eaf48ff69aa75eb7ee2588fe0eb33184cddde5cc1363029ce4d3ebd8bdd6e0e4c24e4fb619abcc9f0ef6bb3848015a35ab3cd5", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "4b7cecfc");
    output.clear();
}

#[test]
fn test_int() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "int 9999", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "6542");
    output.clear();

    ToolArgs::process_line(&mut tool_state, "int 9999999999999999", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "419876651106371");
    output.clear();
}

#[test]
fn test_prime() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "prime 100 -f b58", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "24EiFbSTQcbNhnD99U");
    output.clear();

    ToolArgs::process_line(&mut tool_state, "prime 500 -f b58", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "4qkwPQFisuqFtMHeVpQ8AfTZrMegWcZYV2bE63AASSDRt78Q3RoNPtB2h7xdcvJ6Xfc2HAFK3UYvMSReyWBuia"
    );
    output.clear();
}

#[test]
fn test_bytes() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "bytes 16", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "db7cecfc87a466197ca1264a791a058c"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "bytes 32", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "db7cecfc87a466197ca1264a791a058c00825f2f220c3937b8cbff68cd8c8f6e"
    );
    output.clear();
}

#[test]
fn test_btc() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "btc addr", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "16d5NbPiZMUks5fLNof98ddpF2Cpk3Xi4m"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "btc wif", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "KzH5bXKEwJ7ryigXESxBtbB1mbcbt1czfDbNxQFYSPXV1yJkfRd5"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "btc private", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "5b3ed3844704c7457c03d82bb807f26882e6b073086e025f9d3315214b3fa336"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "btc public", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "037198c1be49c393aec99197fef917a1dee4eed637e2ac804afdf39b3863a1b74b"
    );
    output.clear();
}

#[test]
fn test_password() {
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "password v1", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "XMMQ-KJK9-PEWC-578C-KLL3"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "password v2", &mut output).unwrap();
    assert_eq!(std::str::from_utf8(&output).unwrap(), "4.92692Ghmww");
    output.clear();
}

#[test]
fn test_test_vectors() {
    use digest::Digest;
    let mut tool_state = StandardToolState::default();
    let mut output = Vec::<u8>::new();

    ToolArgs::process_line(&mut tool_state, "secret zero", &mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "Imported DCUUx9UhnhJErcndchjMsZ"
    );
    output.clear();

    ToolArgs::process_line(&mut tool_state, "test-vectors", &mut output).unwrap();
    let hashstr = hex::encode(sha2::Sha256::digest(output.as_slice()).as_slice());
    assert_eq!(
        hashstr.as_str(),
        "9493cfc03e036fbe373e09901dbb03c576b51c7049368f2c60e2898e7bc61ef4"
    );
    output.clear();
}
