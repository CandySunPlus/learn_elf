use std::{fmt, ops::Range};

use derive_more::{Add, Sub};
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::{bitflags, BitFlags};
use nom::{
    bits,
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    multi::{many_m_n, many_till},
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    sequence::tuple,
    Offset,
};

mod parse;

#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("{0}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("Rela segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("StrTab segment not found")]
    StrTabSegmentNotFound,
    #[error("String not found")]
    StringNotFound,
}

#[derive(thiserror::Error, Debug)]
pub enum ReadSymsError {
    #[error("{0:?}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("SymTab section not found")]
    SymTabSectionNotFound,
    #[error("SymTab segment not found")]
    SymTabSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum GetDynamicEntryError {
    #[error("Dynamic entry {0:?} not found")]
    NotFound(DynamicTag),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(le_u64, From::from)(i)
    }

    /// # Safety
    ///
    /// This can create dangling pointers and all sorts of eldritch
    /// errors.
    pub unsafe fn as_ptr<T>(&self) -> *const T {
        std::mem::transmute(self.0 as usize as *const T)
    }

    /// # Safety
    ///
    /// This can create dangling pointers and all sorts of eldritch
    /// errors.
    pub unsafe fn as_mut_ptr<T>(&self) -> *mut T {
        std::mem::transmute(self.0 as usize as *mut T)
    }

    pub unsafe fn as_slice<T>(&self, len: usize) -> &[T] {
        std::slice::from_raw_parts(self.as_ptr(), len)
    }

    pub unsafe fn as_mut_slice<T>(&mut self, len: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }

    pub unsafe fn write(&self, src: &[u8]) {
        std::ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr(), src.len())
    }

    pub unsafe fn set<T>(&self, src: T) {
        *self.as_mut_ptr() = src;
    }
}

impl From<usize> for Addr {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

impl From<u64> for Addr {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Addr> for usize {
    fn from(value: Addr) -> Self {
        value.0 as usize
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

impl DynamicEntry {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i, Self { tag, addr }))
    }
}

#[derive(Debug)]
pub enum SegmentContents {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

pub struct ProgramHeader {
    pub r#type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub contents: SegmentContents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SectionType {
    Null,
    ProgBits,
    SymTab,
    StrTab,
    Rela,
    Hash,
    Dynamic,
    Note,
    NoBits,
    Rel,
    ShLib,
    DynSym,
    InitArray = 14,
    FiniArray,
    PreinitArray,
    Group,
    SymTabShndx,
    Num,
    GnuAttributes = 0x6ffffff5,
    GnuHash,
    GnuLiblist,
    Checksum,
    GnuVerdef = 0x6ffffffd,
    GnuVerneed,
    GnuVersym,
}

impl_parse_for_enum!(SectionType, le_u32);

#[derive(Debug)]
pub struct File<I: AsRef<[u8]>> {
    pub input: I,
    pub contents: FileContents,
}

impl<I: AsRef<[u8]>> File<I> {
    pub fn parse_or_print_error(input: I) -> Option<Self> {
        match FileContents::parse(input.as_ref()) {
            Ok((_, contents)) => Some(File { input, contents }),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {
                    let offset = input.as_ref().offset(input);
                    eprintln!("{err:?} at position {offset}:");
                    eprintln!("{offset:>08x}: {:?}", HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexcpeted nom error"),
        }
    }

    /// Returns a slice of the input, indexed by file offsets
    pub fn file_slice(&self, addr: Addr, len: usize) -> &[u8] {
        &self.input.as_ref()[addr.into()..len]
    }

    /// Returns a slice of the input corresponding to the given section
    pub fn section_slice(&self, section: &SectionHeader) -> &[u8] {
        self.file_slice(section.file_range().start, section.file_range().end.into())
    }

    /// Return a slice of the input corresponding to the given segment
    pub fn segment_slice(&self, segment: &ProgramHeader) -> &[u8] {
        self.file_slice(segment.file_range().start, segment.file_range().end.into())
    }

    /// Returns a slice of the input, indexed by virtual address
    pub fn mem_slice(&self, addr: Addr, len: usize) -> Option<&[u8]> {
        self.contents.segment_containing(addr).map(|segment| {
            let start = (addr - segment.mem_range().start).into();
            &self.segment_slice(segment)[start..start + len]
        })
    }

    /// Return an interator of string value (or u8 slice) of dynamic entries for the given tag
    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = &[u8]> {
        self.dynamic_entries(tag)
            .map(move |addr| self.dynstr_entry(addr))
    }

    /// Read relocation entries from the table pointed to by `DynamicTag::Rela`
    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        let addr = match self.dynamic_entry(DynamicTag::Rela) {
            Some(addr) => addr,
            None => return Ok(vec![]),
        };

        let len = self.get_dynamic_entry(DynamicTag::RelaSz)?;

        let i = self
            .mem_slice(addr, len.into())
            .ok_or(ReadRelaError::RelaSegmentNotFound)?;

        let n = len.0 as usize / Rela::SIZE;
        match many_m_n(n, n, Rela::parse)(i) {
            Ok((_, rela_entries)) => Ok(rela_entries),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(ReadRelaError::ParsingError(format!("{:?}", err)))
            }
            _ => unreachable!(),
        }
    }

    fn string_tab_entry(&self, name: &[u8], offset: Addr) -> &[u8] {
        todo!()
    }

    /// Returns a null-terminated "string" from the ".dynstr" section as an u8 slice
    pub fn dynstr_entry(&self, offset: Addr) -> &[u8] {
        self.string_tab_entry(b".dynstr", offset)
    }
}

impl<I: AsRef<[u8]>> std::ops::Deref for File<I> {
    type Target = FileContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

#[derive(Debug)]
pub struct FileContents {
    pub r#type: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub shstrnds: usize,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    ShLib,
    PHdr,
    TLS,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

#[bitflags]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SegmentFlag {
    Execute,
    Write,
    Read = 0x4,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive, PartialEq, Eq)]
#[repr(u64)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,
    RunPath = 29,
    Flags = 30,
    RelrSz = 35,
    Relr = 36,
    RelrEnt = 37,
    LoOs = 0x60000000,
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
    GnuHash = 0x6ffffef5,
    VerSym = 0x6ffffff0,
    RelaCount = 0x6ffffff9,
    Flags1 = 0x6ffffffb,
    VerDef = 0x6ffffffc,
    VerDefNum = 0x6ffffffd,
    VerNeed = 0x6ffffffe,
    VerNeedNum = 0x6fffffff,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive, PartialEq, Eq)]
#[repr(u32)]
pub enum RelType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum SymBind {
    Local,
    Global,
    Weak,
}

impl_parse_for_bitenum!(SymBind, 4_usize);

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum SymType {
    None,
    Object,
    Func,
    Section,
    File,
    IFunc = 10,
}

impl_parse_for_bitenum!(SymType, 4_usize);

impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);
impl_parse_for_enum!(SegmentType, le_u32);
impl_parse_for_enum!(DynamicTag, le_u64);
impl_parse_for_enum!(RelType, le_u32);
impl_parse_for_enumflags!(SegmentFlag, le_u32);

#[derive(Clone, Copy)]
pub struct SectionIndex(pub u16);

impl fmt::Debug for SectionIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_special() {
            write!(f, "Sepecial({:04x})", self.0)
        } else if self.is_undef() {
            write!(f, "Undef")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl SectionIndex {
    pub fn is_undef(&self) -> bool {
        self.0 == 0
    }

    pub fn is_special(&self) -> bool {
        self.0 >= 0xff00
    }

    pub fn get(&self) -> Option<usize> {
        if self.is_undef() || self.is_special() {
            None
        } else {
            Some(self.0 as usize)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Sym {
    pub name: Addr,
    pub bind: SymBind,
    pub r#type: SymType,
    pub shndx: SectionIndex,
    pub value: Addr,
    pub size: u64,
}

impl Sym {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (name, (bind, r#type), _reserved, shndx, value, size)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            bits(tuple((SymBind::parse, SymType::parse))),
            le_u8,
            map(le_u16, SectionIndex),
            Addr::parse,
            le_u64,
        ))(i)?;

        Ok((
            i,
            Self {
                name,
                bind,
                r#type,
                shndx,
                value,
                size,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SectionHeader {
    pub name: Addr,
    pub r#type: SectionType,
    pub flags: u64,
    pub addr: Addr,
    pub offset: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
}

impl SectionHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (name, r#type, flags, addr, offset, size, link, info, addralign, entsize)) =
            tuple((
                map(le_u32, |x| Addr(x as u64)),
                SectionType::parse,
                le_u64,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                le_u32,
                le_u32,
                Addr::parse,
                Addr::parse,
            ))(i)?;
        Ok((
            i,
            Self {
                name,
                r#type,
                flags,
                addr,
                offset,
                size,
                link,
                info,
                addralign,
                entsize,
            },
        ))
    }

    /// File range where the section is stored
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.size
    }

    /// Memory range where the section is mapped
    pub fn mem_range(&self) -> Range<Addr> {
        self.addr..self.addr + self.size
    }
}

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub r#type: RelType,
    pub sym: u32,
    pub addend: Addr,
}

impl Rela {
    const SIZE: usize = 24;
    fn parse(i: parse::Input) -> parse::Result<Self> {
        map(
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse)),
            |(offset, r#type, sym, addend)| Rela {
                offset,
                r#type,
                sym,
                addend,
            },
        )(i)
    }
}

pub struct HexDump<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{x:02x} ")?;
        }
        Ok(())
    }
}

impl ProgramHeader {
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }

    fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        let (i, (r#type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;
        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
        ))(i)?;

        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match r#type {
            SegmentType::Dynamic => map(
                many_till(
                    DynamicEntry::parse,
                    verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                ),
                |(entries, _last)| SegmentContents::Dynamic(entries),
            )(slice)?,
            _ => (slice, SegmentContents::Unknown),
        };

        Ok((
            i,
            Self {
                r#type,
                flags,
                offset,
                vaddr,
                paddr,
                filesz,
                memsz,
                align,
                contents,
            },
        ))
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X")
            ]
            .iter()
            .map(|&(flag, letter)| {
                if self.flags.contains(flag) {
                    letter
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.r#type
        )
    }
}

impl FileContents {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn get_dynamic_entry(&self, tag: DynamicTag) -> Result<Addr, GetDynamicEntryError> {
        self.dynamic_entry(tag)
            .ok_or(GetDynamicEntryError::NotFound(tag))
    }

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let full_input = i;
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

        let u16_usize = |i| map(le_u16, |x| x as usize)(i);

        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (_flags, _hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) = tuple((&u16_usize, &u16_usize))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((&u16_usize, &u16_usize, &u16_usize))(i)?;

        // Program Headers
        let ph_slices = full_input[ph_offset.into()..].chunks(ph_entsize);
        let mut program_headers = Vec::new();
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        // Section Headers
        let sh_slices = full_input[sh_offset.into()..].chunks(sh_entsize);
        let mut section_headers = Vec::new();
        for sh_slice in sh_slices.take(sh_count) {
            let (_, sh) = SectionHeader::parse(sh_slice)?;
            section_headers.push(sh);
        }

        Ok((
            i,
            Self {
                machine,
                r#type,
                entry_point,
                program_headers,
                section_headers,
                shstrnds: sh_nidx,
            },
        ))
    }

    pub fn section_starting_at(&self, addr: Addr) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| sh.addr == addr)
    }

    pub fn read_syms(&self) -> Result<Vec<Sym>, ReadSymsError> {
        let addr = self.get_dynamic_entry(DynamicTag::SymTab)?;

        let section = self
            .section_starting_at(addr)
            .ok_or(ReadSymsError::SymTabSectionNotFound)?;

        let i = self
            .slice_at(addr)
            .ok_or(ReadSymsError::SymTabSegmentNotFound)?;
        let n = (section.size.0 / section.entsize.0) as usize;

        match many_m_n(n, n, Sym::parse)(i) {
            Ok((_, syms)) => Ok(syms),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(ReadSymsError::ParsingError(format!("{err:?}")))
            }
            _ => unreachable!(),
        }
    }

    pub fn segment_at(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.r#type == SegmentType::Load)
            .find(|ph| ph.mem_range().contains(&addr))
    }

    pub fn segment_of_type(&self, r#type: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.r#type == r#type)
    }

    pub fn section_of_type(&self, r#type: SectionType) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| sh.r#type == r#type)
    }

    /// Attempts to find a Load segment whose memory range contains the given virtual address
    pub fn segment_containing(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .find(|ph| ph.r#type == SegmentType::Load && ph.mem_range().contains(&addr))
    }

    /// Attempts to find the Dynamic segment and return its entries as a slice
    pub fn dynamic_table(&self) -> Option<&[DynamicEntry]> {
        match self.segment_of_type(SegmentType::Dynamic) {
            Some(ProgramHeader {
                contents: SegmentContents::Dynamic(entries),
                ..
            }) => Some(entries),
            _ => None,
        }
    }

    pub fn dynamic_entries(&self, tag: DynamicTag) -> impl Iterator<Item = Addr> + '_ {
        self.dynamic_table()
            .unwrap_or_default()
            .iter()
            .filter(move |e| e.tag == tag)
            .map(|e| e.addr)
    }

    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = String> + '_ {
        self.dynamic_entries(tag)
            .filter_map(move |addr| self.get_string(addr).ok())
    }

    pub fn get_string(&self, offset: Addr) -> Result<String, GetStringError> {
        let addr = self
            .dynamic_entry(DynamicTag::StrTab)
            .ok_or(GetStringError::StrTabNotFound)?;
        let slice = self
            .slice_at(addr + offset)
            .ok_or(GetStringError::StrTabSegmentNotFound)?;
        let string_slice = slice
            .split(|&c| c == 0)
            .next()
            .ok_or(GetStringError::StringNotFound)?;
        Ok(String::from_utf8_lossy(string_slice).into())
    }

    pub fn get_section_name<'a>(
        &self,
        file_contents: &'a [u8],
        offset: Addr,
    ) -> Result<&'a [u8], GetStringError> {
        let tab_start = self.section_headers[self.shstrnds].offset + offset;
        let tab_slice = &file_contents[tab_start.into()..];
        let string_slice = tab_slice
            .split(|&c| c == 0)
            .next()
            .ok_or(GetStringError::StringNotFound)?;
        Ok(string_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enumflags2::BitFlags;

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

    #[test]
    fn try_bitflag() {
        let flags_integer = 6_u32;
        let flags = BitFlags::<SegmentFlag>::from_bits(flags_integer).unwrap();

        assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
        assert_eq!(flags.bits(), flags_integer);

        assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}
