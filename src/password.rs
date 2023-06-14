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

pub trait ExtractPassword {
    /// Generates a very strong, easy-to-read password.
    ///
    /// Despite being easy to read, it is not necessarily easy to type on a cell phone,
    /// making it not ideal for things like WiFi passwords.
    ///
    /// The algorithm skips over commonly confused characters and limits itself
    /// to numbers, upper-case letters, and dashes.
    fn extract_password_v1(&self) -> Result<String>;

    /// Generates a medium-strength password that is optimized for being typed on phone keyboards.
    ///
    /// The generated password is always 12 characters long. Commonly-confused characters are
    /// avoided.
    ///
    /// The algorithm tries to avoid swapping between letters and numbers/symbols too frequently.
    /// It also avoids lower case for letters, except at the boundary between the keyboard
    /// swap.
    ///
    /// The password is guaranteed to include at least one of the following:
    ///
    /// * lower case character
    /// * upper case character
    /// * number
    /// * special symbol
    fn extract_password_v2(&self) -> Result<String>;
}

impl ExtractPassword for Secret {
    fn extract_password_v1(&self) -> Result<String> {
        const SALT: &[u8] = b"\x00Password_v1";
        let mut msecret = self.clone();
        let mut ret = String::new();

        const NUMCAP_LIST: &[char] = &[
            '3', '4', '5', '6', '7', '8', '9', 'A', 'C', 'E', 'G', 'H', 'J', 'K', 'L', 'M', 'N',
            'P', 'Q', 'R', 'U', 'W', 'X', 'Y',
        ];

        for i in 0..20 {
            msecret.mutate_with_salt(SALT)?;
            ret.insert(
                ret.len(),
                NUMCAP_LIST
                    [msecret.extract_u32(u32::try_from(NUMCAP_LIST.len()).unwrap() - 1)? as usize],
            );

            if (i % 4 == 3) && i != 19 {
                ret.insert(ret.len(), '-');
            }
        }

        Ok(ret)
    }

    fn extract_password_v2(&self) -> Result<String> {
        const SALT: &[u8] = b"\x00Password_v2";
        let mut msecret = self.clone();
        let mut ret = String::new();

        const LETTER_LIST: &[char] = &[
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'm', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'w', 'x', 'y', 'z',
        ];

        const CAP_LIST: &[char] = &[
            'A', 'C', 'E', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'U', 'W', 'X', 'Y',
        ];

        // These are all non-confusable numbers and symbols that
        // are visible on both the iOS and Android symbol/number
        // on-screen keyboard.
        const NUMSYM_LIST: &[char] = &[
            '2', '3', '4', '5', '6', '7', '8', '9', '-', '/', ':', '\'', '$', '&', '.', '?', '!',
            '@',
        ];

        let len = 12usize;
        let minbeforeswap = 3;

        loop {
            msecret.mutate_with_salt(SALT)?;
            let swap_point = msecret.extract_usize(len - 1 - minbeforeswap * 2)? + minbeforeswap;

            if msecret.extract_bool()? {
                for _ in 0..swap_point {
                    msecret.mutate_with_salt(SALT)?;
                    ret.insert(
                        ret.len(),
                        LETTER_LIST[msecret.extract_usize(LETTER_LIST.len() - 1)?],
                    );
                }

                msecret.mutate_with_salt(SALT)?;
                ret.insert(
                    ret.len(),
                    CAP_LIST[msecret.extract_usize(CAP_LIST.len() - 1)?],
                );

                for _ in 0..(len - 1 - swap_point) {
                    msecret.mutate_with_salt(SALT)?;
                    ret.insert(
                        ret.len(),
                        NUMSYM_LIST[msecret.extract_usize(NUMSYM_LIST.len() - 1)?],
                    );
                }
            } else {
                for _ in 0..swap_point {
                    msecret.mutate_with_salt(SALT)?;
                    ret.insert(
                        ret.len(),
                        NUMSYM_LIST[msecret.extract_usize(NUMSYM_LIST.len() - 1)?],
                    );
                }

                msecret.mutate_with_salt(SALT)?;
                ret.insert(
                    ret.len(),
                    CAP_LIST[msecret.extract_usize(CAP_LIST.len() - 1)?],
                );

                for _ in 0..(len - 1 - swap_point) {
                    msecret.mutate_with_salt(SALT)?;
                    ret.insert(
                        ret.len(),
                        LETTER_LIST[msecret.extract_usize(LETTER_LIST.len() - 1)?],
                    );
                }
            }

            // Now we check to make sure the password is suitable.
            if ret.contains(|x: char| x.is_ascii_digit())
                && ret.contains(|x: char| x.is_ascii_punctuation())
            {
                // Password is suitable!
                break;
            }

            // Password wasn't suitable, we try again from scratch.
            ret.clear();
        }

        // Sanity check. These should always pass.
        assert!(ret.contains(|x: char| x.is_ascii_uppercase()));
        assert!(ret.contains(|x: char| x.is_ascii_lowercase()));

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_v1() {
        assert_eq!(
            &Secret::ZERO.extract_password_v1().unwrap(),
            "XMMQ-KJK9-PEWC-578C-KLL3"
        );
        assert_eq!(
            &Secret::ZERO
                .subsecret_from_label("1")
                .unwrap()
                .extract_password_v1()
                .unwrap(),
            "YCCQ-WLCX-QUNX-CULR-WQAW"
        );
    }

    #[test]
    fn test_password_v2() {
        assert_eq!(&Secret::ZERO.extract_password_v2().unwrap(), "4.92692Ghmww");
        assert_eq!(
            &Secret::ZERO
                .subsecret_from_label("0")
                .unwrap()
                .extract_password_v2()
                .unwrap(),
            "qbgC'92@&'::"
        );

        // This next one should trigger a "retry".
        assert_eq!(
            &Secret::ZERO
                .subsecret_from_label("5")
                .unwrap()
                .extract_password_v2()
                .unwrap(),
            "&626Xpxskzze"
        );
    }
}
