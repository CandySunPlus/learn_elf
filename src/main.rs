use std::{
    error::Error,
    io::Write,
    process::{Command, Stdio},
};

use argh::FromArgs;

mod name;
mod process;
mod procfs;

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command
struct Args {
    #[argh(subcommand)]
    nested: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Autosym(AutosymArgs),
    Run(RunArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "autosym")]
/// Given a PID, spit out GDB commands to load all .so files
/// mapped in memory.
struct AutosymArgs {
    #[argh(positional)]
    /// the PID of the process to examine
    pid: u32,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "run")]
/// Load and run an ELF execute
struct RunArgs {
    #[argh(positional)]
    /// the absolute path of an executable file to load and ruin
    exec_path: String,
}

fn main() {
    if let Err(e) = do_main() {
        eprintln!("Fatal error: {e}");
    }
}

fn do_main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();
    match args.nested {
        SubCommand::Run(args) => cmd_run(args),
        SubCommand::Autosym(args) => cmd_autosym(args),
    }
}

fn cmd_autosym(args: AutosymArgs) -> Result<(), Box<dyn Error>> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", args.pid))?;

    match procfs::mappings(&maps) {
        Ok((_, mappings)) => {
            println!("Found {} mappings for PID {}", mappings.len(), args.pid);
            println!("Executable file mappings:");
            let xmappings = mappings
                .iter()
                .filter(|m| m.perms.x && m.source.is_file())
                .collect::<Vec<_>>();
            for mapping in &xmappings {
                println!("{mapping:?}");
            }
        }
        Err(e) => panic!("parsing failed: {:?}", e),
    }

    Ok(())
}

fn cmd_run(args: RunArgs) -> Result<(), Box<dyn Error>> {
    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(args.exec_path)?;
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
