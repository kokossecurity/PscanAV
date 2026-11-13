
#[path = "../Scanner/FileScanner.rs"]
mod file_scanner;

use std::env;
use std::path::Path;

fn main() {
    println!("================================");
    println!("          PscanAV v0.1");
    println!("     Linux File Scanner");
    println!("================================");

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("\nUsage: pscanav <directory>");
        return;
    }

    let target = Path::new(&args[1]);

    if !target.exists() {
        eprintln!("\n[ERROR] Directory does not exist.");
        return;
    }

    if !target.is_dir() {
        eprintln!("\n[ERROR] Target must be a directory.");
        return;
    }

    println!("\n[+] Initializing scanner...");
    println!("[+] Target: {}", target.display());
    println!("[+] Starting scan...\n");

    let report = file_scanner::scan_directory(target);

    println!("\n================================");
    println!("         SCAN COMPLETE");
    println!("================================");
    println!("Files scanned: {}", report.files_scanned);
    println!("Errors: {}", report.errors);
    println!("================================");
}
