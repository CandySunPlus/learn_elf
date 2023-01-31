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

    println!("Executing {input_path:?}...");
    let status = Command::new(input_path.as_str()).status()?;
    if !status.success() {
        return Err("process did not exit successfully".into());
    }

    println!("Disassembling {input_path:?}...");

    let code_ph = file
        .program_headers
        .iter()
        .find(|ph| ph.mem_range().contains(&file.entry_point))
        .expect("segment with entry point not found");

    ndisasm(&code_ph.data[..], file.entry_point)?;

    println!("Dynamic entries:");
    if let Some(ds) = file
        .program_headers
        .iter()
        .find(|ph| ph.r#type == delf::SegmentType::Dynamic)
    {
        if let delf::SegmentContents::Dynamic(ref table) = ds.contents {
            for entry in table {
                println!("- {entry:?}");
            }
        }
    }

    println!("Rela entries:");
    let rela_entries = file.read_rela_entries()?;
    for e in &rela_entries {
        println!("{e:#?}");
        if let Some(seg) = file.segment_at(e.offset) {
            println!("... for {seg:#?}");
        }
    }

    let base = 0x400000_usize;

    println!("Mapping {input_path:?} in memory...");

    let mut mappings = Vec::new();

    let phs = file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        .filter(|ph| ph.mem_range().end > ph.mem_range().start);

    for ph in phs {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start = mem_range.start.0 as usize + base;
        let aligned_start = align_to(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr = aligned_start as *mut u8;

        println!("Addr: {addr:p}, Padding: {padding:08x}");

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;
        println!("Copying segment data...");
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(addr.add(padding), ph.data.len()) };
            dst.copy_from_slice(&ph.data[..]);
        }
        println!("Adjusting permissions...");
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

    pause("jmp")?;

    unsafe {
        jmp(new_entry_point);
    }

    Ok(())
}

fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press enter to {reason}...");
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
}

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
