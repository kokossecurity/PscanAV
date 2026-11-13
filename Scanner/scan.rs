
use crate::verifier::{verify_file, Verdict};
use std::{
    fs,
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

    let mut files_scanned = 0usize;
    let mut errors = 0usize;
    let mut suspicious_files: Vec<PathBuf> = Vec::new();
    let mut malicious_files: Vec<PathBuf> = Vec::new();

    let entries = WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.path() != quarantine_dir.as_path());

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("[ERROR] {error}");
                errors += 1;
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        match verify_file(entry.path(), &quarantine_dir) {
            Ok(verification) => {
                files_scanned += 1;

                match verification.verdict {
                    Verdict::NoKnownThreats => {}
                    Verdict::Suspicious => {
                        suspicious_files.push(entry.path().to_path_buf());
                    }
                    Verdict::ConfirmedMalicious => {
                        let display_path = verification
                            .quarantined_to
                            .as_deref()
                            .unwrap_or(entry.path());

                        malicious_files.push(display_path.to_path_buf());
                    }
                }
            }
            Err(error) => {
                eprintln!(
                    "[ERROR] Could not verify {}: {error}",
                    entry.path().display()
                );
                errors += 1;
            }
        }
    }

    println!("\n==================");
    println!("  Scan Completed");
    println!("==================");

    println!("\n[SUMMARY]");
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
