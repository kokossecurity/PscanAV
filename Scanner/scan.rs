
use crate::verifier::{verify_file, Verdict};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

pub fn scan_directory(path: &Path) {
    let root = match fs::canonicalize(path) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("[ERROR] Cannot access directory: {error}");
            return;
        }
    };

    if !root.is_dir() {
        eprintln!("[ERROR] Target is not a directory.");
        return;
    }

    let mut files: Vec<PathBuf> = Vec::new();
    let mut discovery_errors = 0usize;

    println!("[+] Discovering files...");

    for entry in WalkDir::new(&root).follow_links(false) {
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                files.push(entry.path().to_path_buf());
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("[ERROR] {error}");
                discovery_errors += 1;
            }
        }
    }

    let total = files.len();
    let mut scanned = 0usize;
    let mut scan_errors = 0usize;

    let mut suspicious: Vec<PathBuf> = Vec::new();
    let mut malicious: Vec<PathBuf> = Vec::new();

    println!("[+] Found {total} files.");
    println!("[+] Starting scan...\n");

    for file in &files {
        match verify_file(file) {
            Ok(report) => {
                scanned += 1;

                match report.verdict {
                    Verdict::NoKnownThreats => {}
                    Verdict::Suspicious => {
                        suspicious.push(file.clone());
                    }
                    Verdict::ConfirmedMalicious => {
                        malicious.push(file.clone());
                    }
                }
            }
            Err(error) => {
                scan_errors += 1;
                eprintln!("\n[ERROR] {}: {error}", file.display());
            }
        }

        let completed = scanned + scan_errors;
        let percent = if total == 0 {
            100
        } else {
            completed * 100 / total
        };

        let filled = percent * 30 / 100;
        let bar = format!(
            "{}{}",
            "#".repeat(filled),
            "-".repeat(30 - filled)
        );

        print!(
            "\r[{}] {}% ({}/{})",
            bar, percent, completed, total
        );

        let _ = io::stdout().flush();

        println!("\n\n================================");
println!("          Scan Completed");
println!("================================");

    println!("\n[SUMMARY]");
    println!("Files discovered: {total}");
    println!("Files scanned: {scanned}");
    println!("Errors: {}", discovery_errors + scan_errors);
    println!("Suspicious: {}", suspicious.len());
    println!("Malicious: {}", malicious.len());

    if !suspicious.is_empty() {
        println!("\n[SUSPICIOUS FILES]");

        for file in &suspicious {
            println!("{}", file.display());
        }
    }

    if !malicious.is_empty() {
        println!("\n[CONFIRMED MALICIOUS FILES]");

        for file in &malicious {
            println!("{}", file.display());
        }
    }

    println!(
        "\n[!] Detection is heuristic-based; no detection is proof of safety."
    );
}
