use std::{
    cmp::{max, min},
    collections::HashMap,
    fs,
    io::Read,
    ops::Range,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process,
};

use custom_debug_derive::Debug as CustomDebug;
use enumflags2::BitFlags;
use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    #[debug(skip)]
    pub file: delf::File,
    pub mem_range: Range<delf::Addr>,
    pub segments: Vec<Segment>,
    #[debug(skip)]
    pub syms: Vec<delf::Sym>,
}

impl Object {
    pub fn sym_name(&self, index: u32) -> Result<String, RelocationError> {
        self.file
            .get_string(self.syms[index as usize].name)
            .map_err(|_| RelocationError::UnknownSymbolNumber(index))
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
}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("Unknown relocation: {0}")]
    UnknownRelocation(u32),
    #[error("Unimplemented relocation: {0:?}")]
    UnimplementedRelocation(delf::KnownRelType),
    #[error("Unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("Unknown symbol: {0}")]
    UndefinedSymbol(String),
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
    pub map: MemoryMap,
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

        let file = delf::File::parse_or_print_error(&input[..])
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .and_then(|p| p.to_str())
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .map(|p| p.replace("$ORIGIN", origin))
                .inspect(|p| println!("Found RPATH entry {p:?}"))
                .map(PathBuf::from),
        );

        let deps = file
            .dynamic_entry_strings(delf::DynamicTag::Needed)
            .collect::<Vec<_>>();

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
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(mem_size, &[])?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        let segments = load_segments()
            .filter_map(|ph| {
                if ph.memsz.0 > 0 {
                    let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                    let padding = ph.vaddr - vaddr;
                    let offset = ph.offset - padding;
                    let memsz = ph.memsz + padding;
                    let map_res = MemoryMap::new(
                        memsz.into(),
                        &[
                            MapOption::MapReadable,
                            MapOption::MapWritable,
                            MapOption::MapFd(fs_file.as_raw_fd()),
                            MapOption::MapOffset(offset.into()),
                            MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                        ],
                    );
                    Some(map_res.map(|map| Segment {
                        map,
                        padding,
                        flags: ph.flags,
                    }))
                } else {
                    None
                }
            })
            .collect::<Result<_, _>>()?;

        let syms = file.read_syms()?;

        let object = Object {
            path: path.clone(),
            base,
            segments,
            file,
            mem_range,
            syms,
        };

        if path.to_str().unwrap().ends_with("libmsg.so") {
            let msg_addr = unsafe { (base + delf::Addr(0x2000)).as_ptr() };
            dbg!(msg_addr);
            let msg_slice = unsafe { std::slice::from_raw_parts(msg_addr, 0x26) };
            let msg = std::str::from_utf8(msg_slice).unwrap();
            dbg!(msg);
        }

        let index = self.objects.len();
        self.objects.push(object);
        self.objects_by_path.insert(path, index);

        for dep in &deps {
            self.get_object(dep)?;
        }

        Ok(index)
    }

    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        dump_maps("before relocations");
        for obj in self.objects.iter().rev() {
            println!("Applying relocations for {:?}", obj.path);
            match obj.file.read_rela_entries() {
                Ok(rels) => {
                    for rel in rels {
                        println!("Found {rel:?}");
                        match rel.r#type {
                            delf::RelType::Known(t) => match t {
                                delf::KnownRelType::_64 => {
                                    let name = obj.sym_name(rel.sym)?;
                                    println!("Looking up {name:?}");
                                    let (lib, sym) = self
                                        .lookup_symbol(&name, None)?
                                        .ok_or(RelocationError::UndefinedSymbol(name))?;
                                    println!("Found at {:?} in {:?}", sym.value, lib.path);

                                    let offset = obj.base + rel.offset;
                                    let value = sym.value + lib.base + rel.addend;

                                    println!("Value: {value:?}");

                                    unsafe {
                                        *offset.as_mut_ptr() = value.0;
                                    }
                                }
                                delf::KnownRelType::Copy => {
                                    let name = obj.sym_name(rel.sym)?;
                                    let (lib, sym) =
                                        self.lookup_symbol(&name, Some(obj))?.ok_or_else(|| {
                                            RelocationError::UndefinedSymbol(name.clone())
                                        })?;

                                    unsafe {
                                        let src = (sym.value + lib.base).as_ptr();
                                        let dst = (rel.offset + obj.base).as_mut_ptr();
                                        std::ptr::copy_nonoverlapping::<u8>(
                                            src,
                                            dst,
                                            sym.size as usize,
                                        );
                                    }
                                }
                                _ => return Err(RelocationError::UnimplementedRelocation(t)),
                            },
                            delf::RelType::Unknown(num) => {
                                return Err(RelocationError::UnknownRelocation(num))
                            }
                        }
                    }
                }
                Err(err) => println!("Nevermind: {err:?}"),
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

    pub fn lookup_symbol(
        &self,
        name: &str,
        ignore: Option<&Object>,
    ) -> Result<Option<(&Object, &delf::Sym)>, RelocationError> {
        let candidates = self.objects.iter();
        let candidates: Box<dyn Iterator<Item = _>> = if let Some(ignored) = ignore {
            Box::new(candidates.filter(|&obj| !std::ptr::eq(obj, ignored)))
        } else {
            Box::new(candidates)
        };
        for obj in candidates {
            for (i, sym) in obj.syms.iter().enumerate() {
                if obj.sym_name(i as u32)? == name {
                    return Ok(Some((obj, sym)));
                }
            }
        }
        Ok(None)
    }
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

fn dump_maps(msg: &str) {
    println!("======== MEMORY MAPS: {msg}");
    fs::read_to_string(format!("/proc/{pid}/maps", pid = process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello-dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{line}"));
    println!("=============================");
}
