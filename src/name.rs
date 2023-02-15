use core::fmt;
use std::hash::{Hash, Hasher};

#[derive(Clone)]
pub enum Name {
    FromAddr { addr: delf::Addr, len: usize },
    Owned(Vec<u8>),
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
    pub unsafe fn from_addr(addr: delf::Addr) -> Self {
        let len = addr
            .as_slice::<u8>(2048)
            .iter()
            .position(|&c| c == 0)
            .expect("scanned 2048 bytes without finding null-terminator for name");

        Self::FromAddr { addr, len }
    }

    pub fn owned<T: Into<Vec<u8>>>(value: T) -> Self {
        Self::Owned(value.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::FromAddr { addr, len } => unsafe { addr.as_slice(*len) },
            Self::Owned(vec) => &vec[..],
        }
    }
}
