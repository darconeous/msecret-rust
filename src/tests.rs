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

#[test]
fn test_secret_id() {
    assert_eq!(&Secret::ZERO.id().to_string(), "DCUUx9UhnhJErcndchjMsZ");
}

#[test]
fn test_simple_subsecrets() {
    assert_eq!(
        &Secret::ZERO.to_hex(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

    assert_eq!(
        &Secret::ZERO.subsecret_from_label("1").unwrap().to_hex(),
        "3bc1bf8f24ebcd813c4136b9ab3e9f26d50b4da59cfac6c169db905259832e84"
    );
    assert_eq!(
        &Secret::ZERO.subsecret_from_label("2").unwrap().to_hex(),
        "af2cbf24a232eb06eb48072e42cbaa7fc65342e0aabb6801d35ecc08bbbef734"
    );
    assert_eq!(
        &Secret::ZERO.subsecret_from_label("3").unwrap().to_hex(),
        "f085e5eb4a5d34c27b2ff86d527f90bfdc6978c77d89a5d3389eff8ec1a525e2"
    );

    assert_eq!(
        Secret::ZERO.subsecret_from_path("1").unwrap(),
        Secret::try_from_hex("3bc1bf8f24ebcd813c4136b9ab3e9f26d50b4da59cfac6c169db905259832e84")
            .unwrap()
    );
    assert_eq!(
        Secret::ZERO.subsecret_from_path("2").unwrap(),
        Secret::try_from_hex("af2cbf24a232eb06eb48072e42cbaa7fc65342e0aabb6801d35ecc08bbbef734")
            .unwrap()
    );
    assert_eq!(
        Secret::ZERO.subsecret_from_path("3").unwrap(),
        Secret::try_from_hex("f085e5eb4a5d34c27b2ff86d527f90bfdc6978c77d89a5d3389eff8ec1a525e2")
            .unwrap()
    );
}

#[test]
fn test_simple_extract() {
    assert_eq!(
        Secret::ZERO
            .subsecret_from_label("1")
            .unwrap()
            .extract_u32(250)
            .unwrap(),
        29
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_label("2")
            .unwrap()
            .extract_u32(250)
            .unwrap(),
        187
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_label("3")
            .unwrap()
            .extract_u32(250)
            .unwrap(),
        11
    );

    assert_eq!(
        Secret::ZERO
            .subsecret_from_label("1")
            .unwrap()
            .extract_u32(251)
            .unwrap(),
        30
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_label("2")
            .unwrap()
            .extract_u32(251)
            .unwrap(),
        7
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_label("3")
            .unwrap()
            .extract_u32(251)
            .unwrap(),
        214
    );
}

#[test]
fn test_extract_path() {
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        756
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        756
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/a")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        2347
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/a/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        2347
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/a/b/c/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        6773
    );
}

#[test]
fn test_extract_path_chain() {
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        3998
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x@1/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        3998
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x/x/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        7702
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x@2/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        7702
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x/x/x/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        6632
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x@3/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        6632
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x/x/x/x/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        5276
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x@4/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        5276
    );
    assert_eq!(
        Secret::ZERO
            .subsecret_from_path("/x@2/x@2/")
            .unwrap()
            .extract_u32(10001)
            .unwrap(),
        5276
    );
}

#[test]
fn test_extract_bytes() {
    let value = Secret::ZERO
        .subsecret_from_label("1")
        .unwrap()
        .extract_bytes(32)
        .unwrap();
    assert_eq!(
        &value,
        &hex!["4e03168fd7039b3120b6dd0ba5fc1e20f2f817b0a81f2d58663fb107b887ce79"],
        "{:?}",
        hex::encode(&value)
    );

    let value = Secret::ZERO
        .subsecret_from_label("2")
        .unwrap()
        .extract_bytes(32)
        .unwrap();
    assert_eq!(
        &value,
        &hex!["a2cfd030229b321e1f83ce177361cf7797119572bcd9c34f3b056d5c8a67c103"],
        "{:?}",
        hex::encode(&value)
    );

    let value = Secret::ZERO
        .subsecret_from_label("3")
        .unwrap()
        .extract_bytes(32)
        .unwrap();
    assert_eq!(
        &value,
        &hex!["e7d0a040c0bf75094afda5d0f7d90d593c1545fd7daeed9c3ac1e2c4d3f4e3ab"],
        "{:?}",
        hex::encode(&value)
    );
}

#[test]
fn test_parse() {
    let value: Secret = "4e03168fd7039b3120b6dd0ba5fc1e20f2f817b0a81f2d58663fb107b887ce79"
        .parse()
        .unwrap();
    assert_eq!(
        &value.to_string(),
        "4e03168fd7039b3120b6dd0ba5fc1e20f2f817b0a81f2d58663fb107b887ce79"
    );
}

#[test]
fn test_passphrase() {
    let value: Secret = Secret::from_passphrase("This is a passphrase.");
    assert_eq!(
        &value.to_string(),
        "b6d9c13fdeb28d9058957710185218a3fee7fdccde7d39175580c66b8e954d00"
    );
}

#[test]
fn test_parse_error() {
    "4e031".parse::<Secret>().unwrap_err();
}
