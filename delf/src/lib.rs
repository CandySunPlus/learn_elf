use std::fmt;

use derive_more::{Add, Sub};
use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
    Offset,
};

mod parse;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(le_u64, From::from)(i)
    }
}

impl From<u64> for Addr {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug)]
pub struct File {
    pub r#type: Type,
    pub machine: Machine,
    pub entry_point: Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None,
    Rel,
    Exec,
    Dyn,
    Core,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);

pub struct HexDump<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }
        Ok(())
    }
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),
            context("Endianness", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8_usize)),
        ))(i)?;

        let (i, (r#type, machine)) = tuple((Type::parse, Machine::parse))(i)?;
        let (i, _) = context("Version (bits)", verify(le_u32, |&x| x == 1))(i)?;
        let (i, entry_point) = Addr::parse(i)?;

        Ok((
            i,
            Self {
                machine,
                r#type,
                entry_point,
            },
        ))
    }

    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {
                    let offset = i.offset(input);
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexcpeted nom error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_to_u16() {
        assert_eq!(Type::Dyn as u16, 0x3);
    }

    #[test]
    fn type_from_u16() {
        assert_eq!(Type::try_from(0x3), Ok(Type::Dyn));
        assert_eq!(Type::try_from(0xf00d), Err(0xf00d));
    }

    #[test]
    fn try_enums() {
        assert_eq!(Machine::X86_64 as u16, 0x3e);
        assert_eq!(Machine::try_from(0x03), Ok(Machine::X86));
    }
}
