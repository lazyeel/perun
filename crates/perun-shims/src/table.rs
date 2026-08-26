// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Shim registry: declarative API surface.

use linkme::distributed_slice;
use std::collections::HashMap;

use perun_core::loader::{ExternPtr, ImportResolver};

/// Type-erased shim function pointer. Stored as a raw pointer because
/// `fn -> usize` casts are not allowed in const context (linkme requires
/// const-initialized entries). Cast back to `usize` at resolution time.
#[derive(Clone, Copy)]
pub struct ShimFnPtr(pub *const ());
// The pointer is only ever dereferenced as code by the guest; single owner.
unsafe impl Sync for ShimFnPtr {}

/// One registered implementation: Win32 name → function pointer.
pub struct ShimEntry {
    pub name: &'static str,
    pub func: ShimFnPtr,
}

#[distributed_slice]
pub static SHIM_ENTRIES: [ShimEntry];

/// Declarative shim definition. See module docs.
#[macro_export]
macro_rules! win32_api {
    (
        $(#[$meta:meta])*
        pub unsafe extern "win64" fn $name:ident(
            $($arg:ident : $ty:ty),* $(,)?
        ) -> $ret:ty $body:block
    ) => {
        $(#[$meta])*
        #[no_mangle]
        pub unsafe extern "win64" fn $name($($arg: $ty),*) -> $ret $body

        const _: () = {
            #[::linkme::distributed_slice($crate::table::SHIM_ENTRIES)]
            static ENTRY: $crate::table::ShimEntry = $crate::table::ShimEntry {
                name: stringify!($name),
                func: $crate::table::ShimFnPtr($name as *const ()),
            };
        };
    };
    (
        $(#[$meta:meta])*
        unsafe extern "win64" fn $name:ident(
            $($arg:ident : $ty:ty),* $(,)?
        ) -> $ret:ty $body:block
    ) => {
        $crate::win32_api! {
            $(#[$meta])*
            pub unsafe extern "win64" fn $name($($arg: $ty),*) -> $ret $body
        }
    };
    // void return, pub
    (
        $(#[$meta:meta])*
        pub unsafe extern "win64" fn $name:ident(
            $($arg:ident : $ty:ty),* $(,)?
        ) $body:block
    ) => {
        $(#[$meta])*
        #[no_mangle]
        pub unsafe extern "win64" fn $name($($arg: $ty),*) $body

        const _: () = {
            #[::linkme::distributed_slice($crate::table::SHIM_ENTRIES)]
            static ENTRY: $crate::table::ShimEntry = $crate::table::ShimEntry {
                name: stringify!($name),
                func: $crate::table::ShimFnPtr($name as *const ()),
            };
        };
    };
    // void return, private
    (
        $(#[$meta:meta])*
        unsafe extern "win64" fn $name:ident(
            $($arg:ident : $ty:ty),* $(,)?
        ) $body:block
    ) => {
        $crate::win32_api! {
            $(#[$meta])*
            pub unsafe extern "win64" fn $name($($arg: $ty),*) $body
        }
    };
}

/// Flat-name import resolver over the collected shim table.
pub struct ShimTable {
    map: HashMap<&'static str, ExternPtr>,
}

impl ShimTable {
    /// Collect every `win32_api!` registration linked into the process.
    pub fn collect() -> ShimTable {
        let mut map = HashMap::with_capacity(SHIM_ENTRIES.len());
        for e in SHIM_ENTRIES.iter() {
            map.insert(e.name, e.func.0 as usize);
        }
        ShimTable { map }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// All registered names, sorted.
    pub fn names(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.map.keys().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn get(&self, name: &str) -> Option<ExternPtr> {
        self.map.get(name).copied()
    }
}

impl ImportResolver for ShimTable {
    fn resolve(&self, _dll: &str, func: &str) -> Option<ExternPtr> {
        self.get(func)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_collects_builtin_shims() {
        let t = ShimTable::collect();
        assert!(
            t.len() > 50,
            "expected the built-in shim set to be collected, got {}",
            t.len()
        );
        for n in ["HeapAlloc", "CreateFileW", "GetLastError"] {
            assert!(t.get(n).is_some(), "{n} missing from shim table");
        }
    }
}
