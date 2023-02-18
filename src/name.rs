use core::fmt;
use std::{
    hash::{Hash, Hasher},
    ops::Range,
    sync::Arc,
};

use mmap::MemoryMap;

#[derive(Clone)]
pub enum Name {
    Mapped {
        map: Arc<MemoryMap>,
        range: Range<usize>,
    },
    Owned(Vec<u8>),
}

trait MemoryMapExt {
    fn as_slice(&self) -> &[u8];
}

impl MemoryMapExt for MemoryMap {
    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data(), self.len()) }
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(self.as_slice(), other.as_slice())
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(self.as_slice(), state)
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = std::str::from_utf8(self.as_slice()) {
            fmt::Display::fmt(s, f)
        } else {
            fmt::Debug::fmt(self.as_slice(), f)
        }
    }
}

impl Name {
    pub fn mapped(map: &Arc<MemoryMap>, offset: usize) -> Self {
        let len = map
            .as_slice()
            .iter()
            .skip(offset)
            .position(|&c| c == 0)
            .expect("scanned 2048 bytes without finding null-terminator for name");

        Self::Mapped {
            map: map.clone(),
            range: offset..offset + len,
        }
    }

    pub fn owned<T: Into<Vec<u8>>>(value: T) -> Self {
        Self::Owned(value.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Mapped { map, range } => &map.as_slice()[range.clone()],
            Self::Owned(vec) => &vec[..],
        }
    }
}
