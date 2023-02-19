use std::{
    cmp::{max, min},
    collections::HashMap,
    fs,
    io::Read,
    ops::Range,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process,
    sync::Arc,
};

use crate::name::Name;
use custom_debug_derive::Debug as CustomDebug;
use delf::RelType;
use enumflags2::BitFlags;
use mmap::{MapOption, MemoryMap};
use multimap::MultiMap;
use region::{protect, Protection};

#[derive(Debug, Clone)]
pub struct NamedSym {
    sym: delf::Sym,
    name: Name,
}

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    #[debug(skip)]
    pub file: delf::File<Vec<u8>>,
    pub mem_range: Range<delf::Addr>,
    pub segments: Vec<Segment>,
    #[debug(skip)]
    syms: Vec<NamedSym>,
    #[debug(skip)]
    sym_map: MultiMap<Name, NamedSym>,
    #[debug(skip)]
    pub rels: Vec<delf::Rela>,
}

#[derive(Debug, Clone)]
pub struct ObjectSym<'a> {
    obj: &'a Object,
    sym: &'a NamedSym,
}

pub enum ResolvedSym<'a> {
    Defined(ObjectSym<'a>),
    Undefined,
}

impl<'a> ResolvedSym<'a> {
    fn value(&self) -> delf::Addr {
        match self {
            Self::Defined(sym) => sym.value(),
            Self::Undefined => delf::Addr(0x0),
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Defined(sym) => sym.sym.sym.size as _,
            Self::Undefined => 0,
        }
    }
}

impl<'a> ObjectSym<'a> {
    fn value(&self) -> delf::Addr {
        self.obj.base + self.sym.sym.value
    }
}

#[derive(Debug)]
struct ObjectRel<'a> {
    obj: &'a Object,
    rel: &'a delf::Rela,
}

impl<'a> ObjectRel<'a> {
    fn addr(&self) -> delf::Addr {
        self.obj.base + self.rel.offset
    }
}

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
    pub objects_by_path: HashMap<PathBuf, usize>,
    pub search_path: Vec<PathBuf>,
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupoported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error on {0}: {1}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
    #[error("ELF object has no load segments")]
    NoLoadSegments,
    #[error("ELF object could not be mapped in memory: {0}")]
    MapError(#[from] mmap::MapError),
    #[error("Could not read symbols from ELF object: {0}")]
    ReadSymsError(#[from] delf::ReadSymsError),
    #[error("Could not read relocations from ELF object: {0}")]
    ReadRelaError(#[from] delf::ReadRelaError),
}

#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("{0:?}: unimplemented relocation: {1:?}")]
    UnimplementedRelocation(PathBuf, delf::RelType),
    #[error("Unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("Unknown symbol: {0:?}")]
    UndefinedSymbol(NamedSym),
}

pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    fn fresh(self) -> Option<usize> {
        if let Self::Fresh(index) = self {
            Some(index)
        } else {
            None
        }
    }
}

#[derive(custom_debug_derive::Debug)]
pub struct Segment {
    #[debug(skip)]
    pub map: Arc<MemoryMap>,
    pub vaddr_range: Range<delf::Addr>,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Default::default(),
            objects_by_path: Default::default(),
            search_path: vec!["/usr/lib".into()],
        }
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|p| p.join(name).canonicalize().ok())
            .find(|p| p.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    pub fn load_object_and_dependencies<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;

        let mut a = vec![index];

        while !a.is_empty() {
            a = a
                .into_iter()
                .map(|index| &self.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(delf::DynamicTag::Needed))
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect()
        }

        Ok(index)
    }

    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, LoadError> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| LoadError::IO(path.as_ref().to_path_buf(), e))?;

        let mut fs_file = fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        let mut input = Vec::new();

        fs_file
            .read_to_end(&mut input)
            .map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {path:?}");

        let file = delf::File::parse_or_print_error(input)
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .and_then(|p| p.to_str())
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .map(|p| String::from_utf8_lossy(p).to_string())
                .map(|p| p.replace("$ORIGIN", origin))
                .inspect(|p| println!("Found RPATH entry {p:?}"))
                .map(PathBuf::from),
        );

        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|ph| ph.r#type == delf::SegmentType::Load)
        };

        let mem_range = load_segments()
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| match acc {
                None => Some(range),
                Some(acc) => Some(convex_hull(acc, range)),
            })
            .ok_or(LoadError::NoLoadSegments)?;

        let mem_size = (mem_range.end - mem_range.start).into();
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(
            mem_size,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        let segments = load_segments()
            .filter(|ph| ph.memsz.0 > 0)
            .map(|ph| -> Result<_, LoadError> {
                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let filesz = ph.filesz + padding;
                let map = MemoryMap::new(
                    filesz.into(),
                    &[
                        MapOption::MapReadable,
                        MapOption::MapWritable,
                        MapOption::MapExecutable,
                        MapOption::MapFd(fs_file.as_raw_fd()),
                        MapOption::MapOffset(offset.into()),
                        MapOption::MapAddr((base + vaddr).as_ptr()),
                    ],
                )?;

                if ph.memsz > ph.filesz {
                    let mut zero_start = base + ph.mem_range().start + ph.filesz;
                    let zero_len = ph.memsz - ph.filesz;

                    unsafe {
                        for i in zero_start.as_mut_slice(zero_len.into()) {
                            *i = 0_u8;
                        }
                    }
                }

                Ok(Segment {
                    map: Arc::new(map),
                    vaddr_range: vaddr..(ph.vaddr + ph.memsz),
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let syms = file.read_dynsym_entries()?;

        let syms = if syms.is_empty() {
            vec![]
        } else {
            let dynstr = file
                .get_dynamic_entry(delf::DynamicTag::StrTab)
                .unwrap_or_else(|_| panic!("String table not found in {path:?}"));
            let segment = segments
                .iter()
                .find(|seg| seg.vaddr_range.contains(&dynstr))
                .unwrap_or_else(|| panic!("Segment not found for string table in {path:#?}"));

            syms.into_iter()
                .map(|sym| {
                    let name = Name::mapped(
                        &segment.map,
                        (dynstr + sym.name - segment.vaddr_range.start).into(),
                    );
                    NamedSym { sym, name }
                })
                .collect()
        };

        let mut sym_map = MultiMap::new();

        for sym in &syms {
            sym_map.insert(sym.name.clone(), sym.clone())
        }

        let mut rels = Vec::new();
        rels.extend(file.read_rela_entries()?);
        rels.extend(file.read_jmp_rel_entries()?);

        let object = Object {
            path: path.clone(),
            base,
            segments,
            file,
            mem_range,
            syms,
            sym_map,
            rels,
        };

        let index = self.objects.len();
        self.objects.push(object);
        self.objects_by_path.insert(path, index);

        Ok(index)
    }

    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        // dump_maps("before relocations");
        for obj in self.objects.iter().rev() {
            println!("Applying relocations for {:?}", obj.path);
            let rels = self
                .objects
                .iter()
                .rev()
                .flat_map(|obj| obj.rels.iter().map(move |rel| ObjectRel { obj, rel }))
                .collect::<Vec<_>>();
            for rel in rels {
                self.apply_relocation(rel)?;
            }
        }
        Ok(())
    }

    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        for obj in &self.objects {
            for seg in &obj.segments {
                let mut protection = Protection::NONE;
                for flag in seg.flags.iter() {
                    protection |= match flag {
                        delf::SegmentFlag::Read => Protection::READ,
                        delf::SegmentFlag::Write => Protection::WRITE,
                        delf::SegmentFlag::Execute => Protection::EXECUTE,
                    }
                }
                unsafe {
                    protect(seg.map.data(), seg.map.len(), protection)?;
                }
            }
        }
        Ok(())
    }

    pub fn lookup_symbol(&self, wanted: &ObjectSym, ignore_self: bool) -> ResolvedSym {
        for obj in &self.objects {
            if ignore_self && std::ptr::eq(wanted.obj, obj) {
                continue;
            }

            if let Some(syms) = obj.sym_map.get_vec(&wanted.sym.name) {
                if let Some(sym) = syms.iter().find(|sym| !sym.sym.shndx.is_undef()) {
                    return ResolvedSym::Defined(ObjectSym { obj, sym });
                }
            }
        }
        ResolvedSym::Undefined
    }

    fn apply_relocation(&self, objrel: ObjectRel) -> Result<(), RelocationError> {
        let ObjectRel { obj, rel } = objrel;
        let reltype = rel.r#type;
        let addend = rel.addend;

        let wanted = ObjectSym {
            obj,
            sym: &obj.syms[rel.sym as usize],
        };

        let ignore_self = matches!(reltype, RelType::Copy);

        let found = match rel.sym {
            0 => ResolvedSym::Undefined,
            _ => match self.lookup_symbol(&wanted, ignore_self) {
                undef @ ResolvedSym::Undefined => match wanted.sym.sym.bind {
                    delf::SymBind::Weak => undef,
                    _ => return Err(RelocationError::UndefinedSymbol(wanted.sym.clone())),
                },
                x => x,
            },
        };

        match reltype {
            RelType::_64 => unsafe {
                objrel.addr().set(found.value() + addend);
            },
            RelType::Relative => unsafe {
                objrel.addr().set(obj.base + addend);
            },
            RelType::IRelative => unsafe {
                type Selector = extern "C" fn() -> delf::Addr;
                let selector: Selector = std::mem::transmute(obj.base + addend);
                objrel.addr().set(selector());
            },
            RelType::Copy => unsafe {
                objrel.addr().write(found.value().as_slice(found.size()));
            },
            RelType::GlobDat | RelType::JumpSlot => unsafe { objrel.addr().set(found.value()) },
        }
        Ok(())
    }
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

#[allow(dead_code)]
fn dump_maps(msg: &str) {
    println!("======== MEMORY MAPS: {msg}");
    fs::read_to_string(format!("/proc/{pid}/maps", pid = process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello-dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{line}"));
    println!("=============================");
}
