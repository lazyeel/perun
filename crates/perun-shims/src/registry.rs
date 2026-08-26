// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Synthetic registry: a small in-memory stand-in for the Windows registry.
//!
//! ADI-class guests probe `HKLM\Software\Apple Computer, Inc.\...` style keys
//! during initialization and degrade gracefully when they are absent. This
//! store lets a host preseed values (or later load them from an INI file)
//! without implementing the real registry machinery.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

#[derive(Default)]
pub struct Registry {
    /// `"HKEY\\Subkey\\Path"` → value bytes plus a type tag.
    values: Mutex<HashMap<String, RegValue>>,
}

#[derive(Clone, Debug)]
pub struct RegValue {
    pub data: Vec<u8>,
    pub kind: RegType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegType {
    /// Null-terminated string.
    Sz,
    /// 32-bit number.
    Dword,
    /// Raw bytes.
    Binary,
}

impl Default for RegType {
    fn default() -> Self {
        RegType::Binary
    }
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| Registry {
    values: Mutex::new(HashMap::new()),
});

impl Registry {
    pub fn global() -> &'static Registry {
        &REGISTRY
    }

    pub fn set(&self, path: &str, value: RegValue) {
        self.values.lock().unwrap().insert(path.to_string(), value);
    }

    pub fn set_sz(&self, path: &str, s: &str) {
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        self.set(path, RegValue { data, kind: RegType::Sz });
    }

    pub fn set_dword(&self, path: &str, v: u32) {
        self.set(
            path,
            RegValue {
                data: v.to_le_bytes().to_vec(),
                kind: RegType::Dword,
            },
        );
    }

    pub fn get(&self, path: &str) -> Option<RegValue> {
        self.values.lock().unwrap().get(path).cloned()
    }

    /// Win32 `RegOpenKeyExA` semantics: does the key exist?
    /// We treat any stored value path with this prefix as an existing key.
    pub fn key_exists(&self, path: &str) -> bool {
        let p = path.trim_end_matches('\\').to_ascii_uppercase();
        self.values
            .lock()
            .unwrap()
            .keys()
            .any(|k| k.to_ascii_uppercase().starts_with(&p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_roundtrip() {
        let r = Registry::default();
        r.set_dword("HKEY_LOCAL_MACHINE\\Software\\Test\\Answer", 42);
        let v = r.get("HKEY_LOCAL_MACHINE\\Software\\Test\\Answer").unwrap();
        assert_eq!(v.kind, RegType::Dword);
        assert_eq!(u32::from_le_bytes(v.data[..4].try_into().unwrap()), 42);

        assert!(r.key_exists("HKEY_LOCAL_MACHINE\\Software\\Test"));
        assert!(!r.key_exists("HKEY_CURRENT_USER\\Nothing"));
    }
}
