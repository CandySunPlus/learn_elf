use std::{
    env,
    error::Error,
    fs,
    io::Write,
    process::{Command, Stdio},
};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk FILE");
    let input = fs::read(&input_path)?;

    println!("Analyzing {input_path:?}...");

    let file = match delf::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };
    println!("{file:#?}");

    let rela_entries = file.read_rela_entries().unwrap_or_else(|e| {
        println!("Could not read relocations: {e:?}");
        Default::default()
    });

    println!("Found {} rela entries", rela_entries.len());

    for entry in &rela_entries {
        println!("{entry:?}");
    }

    let syms = file.read_syms().unwrap_or_else(|e| {
        println!("Could not read symbol tables: {e:?}");
        Default::default()
    });

    println!(
        "Symbol table @ {:?} contains {} entries",
        file.dynamic_entry(delf::DynamicTag::SymTab).unwrap(),
        syms.len()
    );
    println!(
        "  {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
        "Num", "Value", "Size", "Type", "Bind", "Ndx", "Name"
    );
    for (num, s) in syms.iter().enumerate() {
        println!(
            "  {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
            format!("{}", num),
            format!("{:?}", s.value),
            format!("{:?}", s.size),
            format!("{:?}", s.r#type),
            format!("{:?}", s.bind),
            format!("{:?}", s.shndx),
            format!("{}", file.get_string(s.name).unwrap_or_default()),
        );
    }

    let msg = syms
        .iter()
        .find(|sym| file.get_string(sym.name).unwrap_or_default() == "msg")
        .expect("should find msg in symbol table");
    let msg_slice = file.slice_at(msg.value).expect("shoud find msg in memory");
    let msg_slice = &msg_slice[..msg.size as _];

    println!("msg contents: {:?}", String::from_utf8_lossy(msg_slice));

    let base = 0x400000_usize;

    println!("Loading with base address @ 0x{base:x}");

    let mut mappings = Vec::new();

    let phs = file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        .filter(|ph| ph.mem_range().end > ph.mem_range().start);

    for ph in phs {
        println!("Mapping {:?} - {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start = mem_range.start.0 as usize + base;
        let aligned_start = align_to(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr = aligned_start as *mut u8;

        if padding > 0 {
            println!("(With 0x{padding:08x} bytes of padding at the start)");
        }

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        unsafe {
            std::ptr::copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
        }

        let mut num_relocs = 0;
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                num_relocs += 1;
                unsafe {
                    let real_segment_start = addr.add(padding);
                    let specified_reloc_offset = reloc.offset;
                    let specified_segment_start = mem_range.start;
                    let offset_into_segment = specified_reloc_offset - specified_segment_start;
                    let reloc_addr = real_segment_start.add(offset_into_segment.into()) as *mut u64;

                    match reloc.r#type {
                        delf::RelType::Known(t) => {
                            num_relocs += 1;
                            match t {
                                delf::KnownRelType::Relative => {
                                    let reloc_value = reloc.addend + base.into();
                                    *reloc_addr = reloc_value.0;
                                }
                                t => {
                                    panic!("Unsupported relocation type {t:?}");
                                }
                            }
                        }
                        delf::RelType::Unknown(_) => {}
                    }
                }
            }
        }

        if num_relocs > 0 {
            println!("(Applied {num_relocs} relocations)");
        }

        let mut protection = Protection::NONE;

        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Read => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Execute => Protection::EXECUTE,
            }
        }

        unsafe {
            protect(addr, len, protection)?;
        }

        mappings.push(map);
    }

    let new_entry_point = (file.entry_point + base.into()).into();

    println!("Jumping to entry point @ {new_entry_point:?}...");

    unsafe {
        jmp(new_entry_point);
    }

    Ok(())
}

#[allow(dead_code)]
fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press enter to {reason}...");
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
}

#[allow(dead_code)]
fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", origin.0))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(code)?;
    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

fn align_to(x: usize) -> usize {
    x & !0xFFF
}
