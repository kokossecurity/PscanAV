
#[path = "../verifier/verifier.rs"]
mod verifier;

#[path = "../Scanner/scan.rs"]
mod file_scanner;

#[path = "../engines/yara.rs"]
mod yara;

use std::{env, path::Path};

fn main() {
    println!("================================");
    println!("          PscanAV v0.2");
    println!("     Advanced File Scanner");
    println!("================================");

    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("[ERROR] Usage: pscanav <directory>");
        return;
    }

    let rules_path = Path::new("rules");

    let yara_engine = match yara::YaraEngine::new(rules_path) {
        Ok(engine) => {
            println!("[+] YARA engine initialized.");
            Some(engine)
        }
        Err(error) => {
            eprintln!("[!] YARA unavailable: {error}");
            None
        }
    };

    for target in &args {
        let path = Path::new(target);

        if !path.is_dir() {
            eprintln!("[ERROR] Invalid directory: {}", path.display());
            continue;
        }

        println!("\n[+] Target: {}", path.display());

        file_scanner::scan_directory(path, yara_engine.as_ref());
    }
}
