
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

    let mut suspicious = Vec::new();
    let mut malicious = Vec::new();

    println!("[+] Found {total} files.");
    println!("[+] Starting scan...\n");

    for file in &files {
        match verify_file(file) {
            Ok(report) => {
                scanned += 1;

                match report.verdict {
                    Verdict::NoKnownThreats => {}
                    Verdict::Suspicious => {
                        suspicious.push((
                            file.clone(),
                            report.sha256,
                            report.file_type,
                            report.findings,
                        ));
                    }
                    Verdict::ConfirmedMalicious => {
                        malicious.push((
                            file.clone(),
                            report.sha256,
                            report.file_type,
                            report.findings,
                        ));
                    }
                }
            }
            Err(error) => {
                scan_errors += 1;
                eprintln!("\n[ERROR] {}: {error}", file.display());
            }
        }

        // Each discovered file contributes exactly once.
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
    }

    println!("\n\n==================");
    println!("  Scan Completed");
    println!("==================");

    println!("\n[SUMMARY]");
    println!("Files discovered: {total}");
    println!("Files scanned: {scanned}");
    println!("Discovery errors: {discovery_errors}");
    println!("Scan errors: {scan_errors}");
    println!("Total errors: {}", discovery_errors + scan_errors);
    println!("Suspicious: {}", suspicious.len());
    println!("Malicious: {}", malicious.len());

    if !suspicious.is_empty() {
        println!("\n[SUSPICIOUS FILES]");

        for (file, sha256, file_type, findings) in &suspicious {
            println!("\n{}", file.display());
            println!("  Format: {file_type}");
            println!("  SHA-256: {sha256}");

            for finding in findings {
                println!("  - {finding}");
            }
        }
    }

    if !malicious.is_empty() {
        println!("\n[CONFIRMED MALICIOUS FILES]");

        for (file, sha256, file_type, findings) in &malicious {
            println!("\n{}", file.display());
            println!("  Format: {file_type}");
            println!("  SHA-256: {sha256}");

            for finding in findings {
                println!("  - {finding}");
            }
        }
    }

    println!(
        "\n[!] Detection is heuristic-based; no detection is proof of safety."
    );
}
