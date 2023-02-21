use std::{
    arch::asm,
    cmp::{max, min},
    collections::HashMap,
    ffi::CString,
    fs,
    io::Read,
    mem,
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
    #[debug(skip)]
    pub initializers: Vec<delf::Addr>,
}

impl Object {
    fn symzero(&self) -> ResolvedSym {
        ResolvedSym::Defined(ObjectSym {
            obj: self,
            sym: &self.syms[0],
        })
    }
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

    fn is_indirect(&self) -> bool {
        match self {
            Self::Undefined => false,
            Self::Defined(sym) => matches!(sym.sym.sym.r#type, delf::SymType::IFunc),
        }
    }
}

impl<'a> ObjectSym<'a> {
    fn value(&self) -> delf::Addr {
        let addr = self.sym.sym.value + self.obj.base;
        match self.sym.sym.r#type {
            delf::SymType::IFunc => unsafe {
                let src: extern "C" fn() -> delf::Addr = mem::transmute(addr);
                src()
            },
            _ => addr,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum RelocGroup {
    Direct,
    Indirect,
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

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
#[allow(dead_code)]
pub enum AuxType {
    /// End of vector
    Null = 0,
    /// Entry should be ignored
    Ignore = 1,
    /// File descriptor of program
    ExecFd = 2,
    /// Program headers for program
    PHdr = 3,
    /// Size of program header entry
    PhEnt = 4,
    /// Number of program headers
    PhNum = 5,
    /// System page size
    PageSz = 6,
    /// Base address of interpreter
    Base = 7,
    /// Flags
    Flags = 8,
    /// Entry point of program
    Entry = 9,
    /// Program is not ELF
    NotElf = 10,
    /// Real uid
    Uid = 11,
    /// Effective uid
    EUid = 12,
    /// Real gid
    Gid = 13,
    /// Effective gid
    EGid = 14,
    /// String identifying CPU for optimizations
    Platform = 15,
    /// Arch-dependent hints at CPU capabilities
    HwCap = 16,
    /// Frequency at which times() increments
    ClkTck = 17,
    /// Secure mode boolean
    Secure = 23,
    /// String identifying real platform, may differ from Platform
    BasePlatform = 24,
    /// Address of 16 random bytes
    Random = 25,
    // Extension of HwCap
    HwCap2 = 26,
    /// Filename of program
    ExecFn = 31,

    SysInfo = 32,
    SysInfoEHdr = 33,
}

/// Represents an auxiliary vector.
pub struct Auxv {
    typ: AuxType,
    value: u64,
}

impl Auxv {
    /// A list of all the auxiliary types we know (and care) about
    const KNOWN_TYPES: &'static [AuxType] = &[
        AuxType::ExecFd,
        AuxType::PHdr,
        AuxType::PhEnt,
        AuxType::PhNum,
        AuxType::PageSz,
        AuxType::Base,
        AuxType::Flags,
        AuxType::Entry,
        AuxType::NotElf,
        AuxType::Uid,
        AuxType::EUid,
        AuxType::Gid,
        AuxType::EGid,
        AuxType::Platform,
        AuxType::HwCap,
        AuxType::ClkTck,
        AuxType::Secure,
        AuxType::BasePlatform,
        AuxType::Random,
        AuxType::HwCap2,
        AuxType::ExecFn,
        AuxType::SysInfo,
        AuxType::SysInfoEHdr,
    ];

    /// Get an auxiliary vector value with the help of libc.
    pub fn get(typ: AuxType) -> Option<Self> {
        extern "C" {
            /// From libc
            fn getauxval(typ: u64) -> u64;
        }

        unsafe {
            match getauxval(typ as u64) {
                0 => None,
                value => Some(Self { typ, value }),
            }
        }
    }

    /// Returns a list of all aux vectors passed to us _that we know about_.
    pub fn get_known() -> Vec<Self> {
        Self::KNOWN_TYPES
            .iter()
            .copied()
            .filter_map(Self::get)
            .collect()
    }
}

#[derive(Debug)]
pub struct TLS {
    offsets: HashMap<delf::Addr, delf::Addr>,
    block: Vec<u8>,
    tcb_addr: delf::Addr,
}

pub struct Loader {
    pub objects: Vec<Object>,
    pub objects_by_path: HashMap<PathBuf, usize>,
    pub search_path: Vec<PathBuf>,
}

pub trait ProcessState {
    fn loader(&self) -> &Loader;
}

#[derive(Debug)]
pub struct Process<S: ProcessState> {
    pub state: S,
}

pub struct Loading {
    pub loader: Loader,
}

impl ProcessState for Loading {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub struct TLSAllocated {
    loader: Loader,
    pub tls: TLS,
}

impl ProcessState for TLSAllocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub struct Relocated {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for Relocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub struct TLSInitialized {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for TLSInitialized {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub struct Protected {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for Protected {
    fn loader(&self) -> &Loader {
        &self.loader
    }
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

impl Process<Loading> {
    pub fn new() -> Self {
        Self {
            state: Loading {
                loader: Loader {
                    objects: Vec::new(),
                    objects_by_path: HashMap::new(),
                    search_path: vec!["/usr/lib".into()],
                },
            },
        }
    }

    pub fn patch_libc(&self) {
        let mut stub_map = HashMap::new();

        stub_map.insert("_dl_addr", vec![0x48, 0x31, 0xc0, 0xc3]);

        stub_map.insert(
            "exit",
            vec![0x48, 0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05],
        );

        let pattern = "/libc-2.";
        let libc = match self
            .state
            .loader
            .objects
            .iter()
            .find(|&obj| obj.path.to_string_lossy().contains(pattern))
        {
            Some(x) => x,
            None => {
                println!("Warning: could not find libc to patch!");
                return;
            }
        };

        for (name, instructions) in stub_map {
            let name = Name::owned(name);
            let sym = match libc.sym_map.get(&name) {
                Some(sym) => ObjectSym { obj: libc, sym },
                None => {
                    println!("expected to find symbol {name:?} in {:?}", libc.path);
                    continue;
                }
            };

            println!("Patching libc function {:?} ({:?})", sym.value(), name);
            unsafe {
                sym.value().write(&instructions);
            }
        }
    }

    pub fn allocate_tls(mut self) -> Process<TLSAllocated> {
        let mut offsets = HashMap::new();
        let mut storage_space = 0;
        for obj in &mut self.state.loader.objects {
            let needed = obj
                .file
                .segment_of_type(delf::SegmentType::TLS)
                .map(|ph| ph.memsz.0)
                .unwrap_or_default();

            if needed > 0 {
                let offset = delf::Addr(storage_space + needed);

                offsets.insert(obj.base, offset);
                storage_space += needed;
            }
        }

        let tcbhead_size = 704;
        let total_size = storage_space + tcbhead_size;

        let mut block = Vec::with_capacity(total_size as _);

        let tcb_addr = delf::Addr(block.as_ptr() as u64 + storage_space);

        // for _ in 0..storage_space {
        //     block.push(0u8);
        // }
        block.resize((total_size + storage_space) as _, 0u8);

        // Build a "somewhat fake" tcbhead structure
        block.extend(&tcb_addr.0.to_le_bytes()); // tcb
        block.extend(&0_u64.to_le_bytes()); // dtv
        block.extend(&tcb_addr.0.to_le_bytes()); // thread pointer
        block.extend(&0_u32.to_le_bytes()); // multiple_threads
        block.extend(&0_u32.to_le_bytes()); // gscope_flag
        block.extend(&0_u64.to_le_bytes()); // sysinfo
        block.extend(&0xDEADBEEF_u64.to_le_bytes()); // stack guard
        block.extend(&0xFEEDFACE_u64.to_le_bytes()); // pointer guard

        while block.len() < block.capacity() {
            block.push(0u8);
        }

        let tls = TLS {
            offsets,
            block,
            tcb_addr,
        };

        Process {
            state: TLSAllocated {
                loader: self.state.loader,
                tls,
            },
        }
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.state
            .loader
            .search_path
            .iter()
            .filter_map(|p| p.join(name).canonicalize().ok())
            .find(|p| p.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.state
            .loader
            .objects_by_path
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
                .map(|index| &self.state.loader.objects[index].file)
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

        self.state.loader.search_path.extend(
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

        let mut initializers = Vec::new();

        if let Some(init) = file.dynamic_entry(delf::DynamicTag::Init) {
            let init = init + base;
            initializers.push(init);
        }

        if let Some(init_array) = file.dynamic_entry(delf::DynamicTag::InitArray) {
            if let Some(init_array_sz) = file.dynamic_entry(delf::DynamicTag::InitArraySz) {
                let init_array = base + init_array;
                let n = init_array_sz.0 as usize / mem::size_of::<delf::Addr>();
                let inits = unsafe { init_array.as_slice::<delf::Addr>(n) };
                initializers.extend(inits.iter().map(|&init| init + base))
            }
        }

        let object = Object {
            path: path.clone(),
            base,
            segments,
            file,
            mem_range,
            syms,
            sym_map,
            rels,
            initializers,
        };

        let index = self.state.loader.objects.len();
        self.state.loader.objects.push(object);
        self.state.loader.objects_by_path.insert(path, index);

        Ok(index)
    }
}

impl Process<TLSAllocated> {
    pub fn apply_relocations(self) -> Result<Process<Relocated>, RelocationError> {
        // dump_maps("before relocations");
        let mut rels = self
            .state
            .loader
            .objects
            .iter()
            .rev()
            .flat_map(|obj| obj.rels.iter().map(move |rel| ObjectRel { obj, rel }))
            .collect::<Vec<_>>();

        for &group in &[RelocGroup::Direct, RelocGroup::Indirect] {
            println!("Applying {group:?} relocations ({} left)", rels.len());
            rels = rels
                .into_iter()
                .map(|objrel| self.apply_relocation(objrel, group))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect();
        }

        let res = Process {
            state: Relocated {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        };

        Ok(res)
    }

    fn apply_relocation<'a>(
        &self,
        objrel: ObjectRel<'a>,
        group: RelocGroup,
    ) -> Result<Option<ObjectRel<'a>>, RelocationError> {
        let ObjectRel { obj, rel } = objrel;
        let reltype = rel.r#type;
        let addend = rel.addend;

        let wanted = ObjectSym {
            obj,
            sym: &obj.syms[rel.sym as usize],
        };

        let ignore_self = matches!(reltype, RelType::Copy);

        let found = match rel.sym {
            0 => obj.symzero(),
            _ => match self.lookup_symbol(&wanted, ignore_self) {
                undef @ ResolvedSym::Undefined => match wanted.sym.sym.bind {
                    delf::SymBind::Weak => undef,
                    _ => return Err(RelocationError::UndefinedSymbol(wanted.sym.clone())),
                },
                x => x,
            },
        };

        if let RelocGroup::Direct = group {
            if reltype == RelType::IRelative || found.is_indirect() {
                return Ok(Some(objrel));
            }
        }

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
            RelType::TPOff64 => unsafe {
                if let ResolvedSym::Defined(sym) = found {
                    let obj_offset =
                        self.state
                            .tls
                            .offsets
                            .get(&sym.obj.base)
                            .unwrap_or_else(|| {
                                panic!(
                                    "No thread-local storage allocated for object {:?}",
                                    sym.obj.file
                                )
                            });

                    let obj_offset = -(obj_offset.0 as i64);

                    let offset =
                        obj_offset + sym.sym.sym.value.0 as i64 + objrel.rel.addend.0 as i64;

                    objrel.addr().set(offset);
                }
            },
        }
        Ok(None)
    }
}

impl Process<Relocated> {
    pub fn initialize_tls(self) -> Process<TLSInitialized> {
        let tls = &self.state.tls;

        for obj in &self.state.loader.objects {
            if let Some(ph) = obj.file.segment_of_type(delf::SegmentType::TLS) {
                if let Some(offset) = tls.offsets.get(&obj.base).cloned() {
                    unsafe {
                        (tls.tcb_addr - offset)
                            .write((ph.vaddr + obj.base).as_slice(ph.filesz.into()));
                    }
                }
            }
        }

        Process {
            state: TLSInitialized {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        }
    }
}

impl Process<TLSInitialized> {
    pub fn adjust_protections(self) -> Result<Process<Protected>, region::Error> {
        for obj in &self.state.loader.objects {
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

        Ok(Process {
            state: Protected {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        })
    }
}

pub struct StartOptions {
    pub exec_index: usize,
    pub args: Vec<CString>,
    pub env: Vec<CString>,
    pub auxv: Vec<Auxv>,
}

impl Process<Protected> {
    pub fn start(self, opts: &StartOptions) -> ! {
        let exec = &self.state.loader.objects[opts.exec_index];
        let entry_point = exec.file.entry_point + exec.base;
        let stack = Self::build_stack(opts);
        let initializers = self.initializers();

        let argc = opts.args.len();
        let mut argv = opts.args.iter().map(|x| x.as_ptr()).collect::<Vec<_>>();
        argv.push(std::ptr::null());
        let mut envp = opts.env.iter().map(|x| x.as_ptr()).collect::<Vec<_>>();
        envp.push(std::ptr::null());

        unsafe {
            set_fs(self.state.tls.tcb_addr.0);

            for (_, init) in initializers {
                call_init(init, argc as _, argv.as_ptr(), envp.as_ptr());
            }

            jmp(entry_point.as_ptr(), stack.as_ptr(), stack.len())
        };
    }

    fn build_stack(opts: &StartOptions) -> Vec<u64> {
        let mut stack = Vec::new();

        let null = 0_u64;

        macro_rules! push {
            ($x:expr) => {
                stack.push($x as u64)
            };
        }

        // NOTE: everything is pushed in reverse order

        // argc
        push!(opts.args.len());

        // argv
        for v in &opts.args {
            push!(v.as_ptr());
        }
        push!(null);

        // envp
        for v in &opts.env {
            push!(v.as_ptr());
        }
        push!(null);

        // auxv
        for v in &opts.auxv {
            push!(v.typ);
            push!(v.value);
        }
        push!(AuxType::Null);
        push!(null);

        // Align stack to 16-byte boundary:
        if stack.len() % 2 == 1 {
            push!(0);
        }

        stack
    }
}

impl<S: ProcessState> Process<S> {
    fn initializers(&self) -> Vec<(&Object, delf::Addr)> {
        let mut res = Vec::new();
        for obj in self.state.loader().objects.iter().rev() {
            res.extend(obj.initializers.iter().map(|&init| (obj, init)));
        }
        res
    }

    fn lookup_symbol(&self, wanted: &ObjectSym, ignore_self: bool) -> ResolvedSym {
        for obj in &self.state.loader().objects {
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
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

/// Jump to some random memory address
///
/// # Safety
/// Look, this should be obvious, but you're in for some real crazy shit if
/// if you're trying to jump to random instructions in memory.
#[inline(never)]
#[allow(named_asm_labels)]
unsafe fn jmp(entry_point: *const u8, stack_contents: *const u64, qword_count: usize) -> ! {
    asm!(
        // allocate (qword_count * 8) bytes
        "mov {tmp}, {qword_count}",
        "sal {tmp}, 3",
        "sub rsp, {tmp}",

        ".l1:",
        // start at i = (n-1)
        "sub {qword_count}, 1",
        // copy qwords to the stack
        "mov {tmp}, QWORD PTR [{stack_contents}+{qword_count}*8]",
        "mov QWORD PTR [rsp+{qword_count}*8], {tmp}",
        // loop if i isn't zero, break otherwise
        "test {qword_count}, {qword_count}",
        "jnz .l1",

        "jmp {entry_point}",

        entry_point = in(reg) entry_point,
        stack_contents = in(reg) stack_contents,
        qword_count = in(reg) qword_count,
        tmp = out(reg) _,
    );

    // Tell LLVM we never return. Will throw a SIGILL if we somehow end up
    // executing this code.
    asm!("ud2", options(noreturn));
}

/// Set the `fs` register to something.
///
/// # Safety
/// After calling this there are a *lot* of things you should avoid doing. For
/// example:
///
/// - Calling `println!` will lock stdout, and locks use thread-local storage,
///   so that will crash now.
/// - Allocating memory on the heap will call `malloc`, and malloc uses
///   thread-local storage, so that will also crash.
/// - etc, etc... just don't do lots of stuff after calling this!
#[inline(never)]
unsafe fn set_fs(addr: u64) {
    let syscall_number: u64 = 158;
    let arch_set_fs: u64 = 0x1002;

    asm!(
        "syscall",
        inout("rax") syscall_number => _,
        in("rdi") arch_set_fs,
        in("rsi") addr,
        lateout("rcx") _, lateout("r11") _,
    )
}

/// Call an ELF initializer function.
///
/// # Safety
/// You must be a creationist.
#[inline(never)]
unsafe fn call_init(addr: delf::Addr, argc: i32, argv: *const *const i8, envp: *const *const i8) {
    let init: extern "C" fn(argc: i32, argv: *const *const i8, envp: *const *const i8) =
        std::mem::transmute(addr.0);

    init(argc, argv, envp);
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
