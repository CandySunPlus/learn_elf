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

    println!("Mapping {input_path:?} in memory...");

    let mut mappings = Vec::new();

    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();
        let addr = mem_range.start.0 as *mut u8;
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;
        println!("Copying segment data...");
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) };
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

    println!("Jumping to entry point @ {:?}...", file.entry_point);
    pause("jmp")?;

    unsafe {
        jmp(file.entry_point.0 as _);
    }

    Ok(())
}

fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press enter to {}...", reason);
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
