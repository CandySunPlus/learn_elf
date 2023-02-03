use std::{
    cmp::{max, min},
    collections::HashMap,
    fs,
    io::Read,
    ops::Range,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use custom_debug_derive::Debug as CustomDebug;
use mmap::{MapOption, MemoryMap};

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    #[debug(skip)]
    pub file: delf::File,
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,
    pub mem_range: Range<delf::Addr>,
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
        let mem_map = MemoryMap::new(mem_size, &[])?;
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        let maps = load_segments()
            .map(|ph| {
                println!("Mapping {ph:#?}");
                MemoryMap::new(
                    ph.memsz.into(),
                    &[
                        MapOption::MapFd(fs_file.as_raw_fd()),
                        MapOption::MapOffset(ph.offset.into()),
                        MapOption::MapAddr(unsafe { (base + ph.vaddr).as_ptr() }),
                    ],
                )
            })
            .collect::<Result<_, _>>()?;

        let index = self.objects.len();

        let object = Object {
            path: path.clone(),
            base,
            maps,
            file,
            mem_range,
        };
        self.objects.push(object);
        self.objects_by_path.insert(path, index);

        for dep in &deps {
            self.get_object(dep)?;
        }

        Ok(index)
    }
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}
