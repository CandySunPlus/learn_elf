use std::{
    env,
    error::Error,
    io::Write,
    process::{Command, Stdio},
};

mod name;
mod process;

fn main() {
    if let Err(e) = do_main() {
        eprintln!("Fatal error: {e}");
    }
}

fn do_main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk FILE");

    println!("Analyzing {input_path:?}...");
    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(input_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exec_obj = &proc.objects[exec_index];
    let entry_point = exec_obj.file.entry_point + exec_obj.base;
    unsafe { jmp(entry_point.as_ptr()) };

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

#[allow(dead_code)]
unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

#[allow(dead_code)]
fn align_to(x: usize) -> usize {
    x & !0xFFF
}
