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
use std::collections::{HashMap, HashSet};

/// Trait for representing a tool or engine which manages secrets.
pub trait ToolState: AsMut<Self> {
    type Secret: Derivable;

    /// Returns the root secret, if available.
    fn root_secret(&self) -> Result<Self::Secret>;

    /// Returns the secret at the current keypath, if available.
    fn current_secret(&self) -> Result<Self::Secret>;

    /// Imports a [`Secret`] into the root keypath for the tool and resets the keypath to '/'.
    fn import(&mut self, secret: &Secret) -> Result;

    /// Exports the secret at the current keypath as a [`Secret`], if available.
    ///
    /// This may or may not be possible depending on the permission settings
    /// of the underlying tool.
    fn export(&self) -> Result<Secret>;

    /// Generates a new random root secret and resets the current keypath to `/`.
    fn generate(&mut self) -> Result;

    /// Loads the root secret identified by `path` and sets the current keypath to `/`.
    ///
    /// Note that, depending on the underlying tool implementation, this may or
    /// may not be an actual local file.
    fn load(&mut self, path: &Path) -> Result;

    /// Saves the root secret to the location identified by `path`.
    ///
    /// Note that, depending on the underlying tool implementation, this may or
    /// may not be an actual local file.
    fn save(&self, path: &Path) -> Result;

    /// Returns the current tool keypath as a [`String`].
    fn get_keypath(&self) -> Result<String>;

    /// Updates the current keypath based on the given `relpath`.
    fn update_keypath(&mut self, relpath: &str) -> Result;

    fn key_map_mut(&mut self) -> &mut KeyMap;
}

#[derive(Debug, Default)]
pub struct KeyMap {
    pub(crate) children: HashMap<String, KeyMap>,
    pub(crate) primitives: HashSet<String>,
}

impl KeyMap {
    pub fn get_primitives(&self) -> impl Iterator<Item = &str> {
        self.primitives.iter().map(|x| x.as_str())
    }

    pub fn add_primitive<T: Into<String>>(&mut self, primitive: T) {
        self.primitives.insert(primitive.into());
    }

    pub fn get_children(&self) -> impl Iterator<Item = &str> {
        self.children.keys().map(|x| x.as_str())
    }

    pub fn get_child<T: AsRef<str>>(&self, child: T) -> Option<&KeyMap> {
        self.children.get(child.as_ref())
    }

    pub fn get_child_mut<T: AsRef<str>>(&mut self, child: T) -> Option<&mut KeyMap> {
        self.children.get_mut(child.as_ref())
    }

    pub fn get_key_map_from_iter<'a, T: IntoIterator<Item = &'a str>>(
        &self,
        iter: T,
    ) -> Option<&KeyMap> {
        let mut iter = iter.into_iter();
        if let Some(label) = iter.next() {
            if let Some(keymap) = self.children.get(label) {
                keymap.get_key_map_from_iter(iter)
            } else {
                None
            }
        } else {
            Some(self)
        }
    }

    pub fn get_key_map<T: AsRef<str>>(&self, keypath: T) -> Option<&KeyMap> {
        self.get_key_map_from_iter(keypath.as_ref().split('/').filter(|x| !x.is_empty()))
    }

    pub fn update_from_iter<'a, T: IntoIterator<Item = &'a str>>(
        &mut self,
        iter: T,
    ) -> Option<&mut KeyMap> {
        let mut iter = iter.into_iter();
        if let Some(label) = iter.next() {
            let keymap = self
                .children
                .entry(label.to_string())
                .or_default();
            keymap.update_from_iter(iter)
        } else {
            Some(self)
        }
    }

    pub fn update<T: AsRef<str>>(&mut self, keypath: T) -> Option<&mut KeyMap> {
        self.update_from_iter(keypath.as_ref().split('/').filter(|x| !x.is_empty()))
    }
}

#[derive(Debug)]
pub struct StandardToolState {
    keypath: String,
    secret: Option<Secret>,
    key_map: KeyMap,
}

impl Default for StandardToolState {
    fn default() -> Self {
        StandardToolState {
            keypath: "/".to_string(),
            secret: None,
            key_map: Default::default(),
        }
    }
}

impl StandardToolState {
    pub fn reset(&mut self) {
        *self = Self::default()
    }
}

impl AsRef<StandardToolState> for StandardToolState {
    fn as_ref(&self) -> &StandardToolState {
        self
    }
}

impl AsMut<StandardToolState> for StandardToolState {
    fn as_mut(&mut self) -> &mut StandardToolState {
        self
    }
}

impl ToolState for StandardToolState {
    type Secret = Secret;

    fn root_secret(&self) -> Result<Self::Secret> {
        self.secret.clone().ok_or(format_err!("No secret set"))
    }

    fn current_secret(&self) -> Result<Self::Secret> {
        if let Some(secret) = self.secret.as_ref() {
            secret.subsecret_from_path(&self.keypath)
        } else {
            bail!("No secret set.");
        }
    }

    fn import(&mut self, secret: &Secret) -> Result<()> {
        self.reset();
        self.secret = Some(secret.clone());
        Ok(())
    }

    fn export(&self) -> Result<Secret> {
        self.current_secret()
    }

    fn generate(&mut self) -> Result<()> {
        self.reset();
        self.secret = Some(Secret::generate());
        Ok(())
    }

    fn load(&mut self, path: &Path) -> Result<()> {
        let data = std::fs::read(path)?;
        self.reset();
        self.secret = Some(Secret::try_from_bytes_or_hex(data)?);
        Ok(())
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(secret) = &self.secret {
            std::fs::write(path, secret.as_bytes())?;
        } else {
            bail!("No secret set.");
        }
        Ok(())
    }

    fn get_keypath(&self) -> Result<String> {
        Ok(self.keypath.clone())
    }

    fn update_keypath(&mut self, relpath: &str) -> Result<()> {
        if relpath.starts_with('/') {
            // Path is absolute.
            self.keypath = relpath.to_string();
            return Ok(());
        }

        let mut path: Vec<String> = self
            .keypath
            .split('/')
            .filter_map(|w| {
                if w.is_empty() {
                    None
                } else {
                    Some(w.to_string())
                }
            })
            .collect();

        for label in relpath.split('/').filter(|w| !w.is_empty()) {
            match label {
                "." => {
                    continue;
                }
                ".." => {
                    path.pop();
                }
                label => {
                    path.push(label.to_string());
                }
            };
        }

        path.insert(0, String::new());
        self.keypath = path.join("/");
        if self.keypath.is_empty() {
            self.keypath.insert(0, '/');
        }

        Ok(())
    }

    fn key_map_mut(&mut self) -> &mut KeyMap {
        &mut self.key_map
    }
}
