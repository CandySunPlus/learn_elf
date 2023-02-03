use std::{
    fs,
    path::{Path, PathBuf},
};

use custom_debug_derive::Debug as CustomDebug;
use mmap::MemoryMap;

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    #[debug(skip)]
    pub file: delf::File,
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,
}

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
    pub search_path: Vec<PathBuf>,
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Default::default(),
            search_path: Default::default(),
        }
    }

    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> &Object {
        let path = path.as_ref().canonicalize().unwrap();
        let input = fs::read(&path).unwrap();

        println!("Loading {path:?}");
        let file = delf::File::parse_or_print_error(&input[..]).unwrap();

        let origin = path.parent().unwrap().to_str().unwrap();

        for rpath in file.dynamic_entry_strings(delf::DynamicTag::RPath) {
            let rpath = rpath.replace("$ORIGIN", &origin);
            println!("Found RPATH entry {rpath:?}");
            self.search_path.push(PathBuf::from(rpath));
        }

        let object = Object {
            path,
            base: delf::Addr(0x400000),
            maps: Default::default(),
            file,
        };
        self.objects.push(object);
        self.objects.last().unwrap()
    }
}
