
#[path = "../verifier/verifier.rs"]
mod verifier;

#[path = "../Scanner/scan.rs"]
mod file_scanner;

use std::{env, path::Path};

fn main() {
    println!("================================");
    println!("          PscanAV v0.1");
    println!("     Linux File Scanner");
    println!("================================");

    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("\n[ERROR] No scan targets provided.");
        return;
    }

    println!("\n[+] Initializing PscanAV...");
    println!("[+] Scan targets: {}", args.len());

    for target in &args {
        let path = Path::new(target);

        if !path.is_dir() {
            eprintln!("\n[ERROR] Invalid directory: {}", path.display());
            continue;
        }

        println!("\n================================");
        println!("[+] Target: {}", path.display());
        println!("================================");

        file_scanner::scan_directory(path);
    }

    println!("\n[+] All scan targets processed.");
}
