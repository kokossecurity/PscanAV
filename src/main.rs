
#[path = "../Verifier/verify.rs"]
mod verifier;

#[path = "../Scanner/scan.rs"]
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
        eprintln!("\nUsage: pscanav <directory>");
        return;
    }

    let target = Path::new(&args[1]);

    if !target.is_dir() {
        eprintln!("\n[ERROR] Invalid directory.");
        return;
    }

    println!("\n[+] Initializing PscanAV...");
    println!("[+] Target: {}", target.display());
    println!("[+] Starting scan...\n");

    file_scanner::scan_directory(target);
}
