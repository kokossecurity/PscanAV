
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

    let quarantine_dir = root.join(".pscanav-quarantine");

    let mut files: Vec<PathBuf> = Vec::new();
    let mut errors = 0usize;

    println!("[+] Discovering files...");

    for entry in WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.path() != quarantine_dir.as_path())
    {
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                files.push(entry.path().to_path_buf());
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("[ERROR] {error}");
                errors += 1;
            }
        }
    }

    let total = files.len();
    let mut files_scanned = 0usize;

    let mut suspicious_files = Vec::new();
    let mut malicious_files = Vec::new();

    println!("[+] Found {total} files.");
    println!("[+] Starting scan...\n");

    for file in &files {
        match verify_file(file, &quarantine_dir) {
            Ok(report) => {
                files_scanned += 1;

                match report.verdict {
                    Verdict::NoKnownThreats => {}
                    Verdict::Suspicious => {
                        suspicious_files.push(file.clone());
                    }
                    Verdict::ConfirmedMalicious => {
                        let display_path = report
                            .quarantined_to
                            .as_deref()
                            .unwrap_or(file);

                        malicious_files.push(display_path.to_path_buf());
                    }
                }
            }
            Err(error) => {
                errors += 1;
                eprintln!(
                    "\n[ERROR] {}: {error}",
                    file.display()
                );
            }
        }

        let progress = files_scanned + errors;
        let percent = if total == 0 {
            100
        } else {
            progress * 100 / total
        };

        let bar_length = 30;
        let filled = percent * bar_length / 100;

        let bar = format!(
            "{}{}",
            "#".repeat(filled),
            "-".repeat(bar_length - filled)
        );

        print!(
            "\r[{}] {}% ({}/{})",
            bar, percent, progress, total
        );

        let _ = io::stdout().flush();
    }

    println!("\n\n==================");
    println!("  Scan Completed");
    println!("==================");

    println!("\n[SUMMARY]");
    println!("Files discovered: {total}");
    println!("Files scanned: {files_scanned}");
    println!("Errors: {errors}");
    println!("Suspicious: {}", suspicious_files.len());
    println!("Malicious: {}", malicious_files.len());

    if !suspicious_files.is_empty() {
        println!("\n[SUSPICIOUS]");
        for file in &suspicious_files {
            println!("{}", file.display());
        }
    }

    if !malicious_files.is_empty() {
        println!("\n[MALICIOUS]");
        for file in &malicious_files {
            println!("{}", file.display());
        }
    }
}
