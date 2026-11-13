
use crate::verifier::{verify_file, Verdict};
use crate::yara::YaraEngine;

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use walkdir::WalkDir;

pub fn scan_directory(path: &Path, yara: Option<&YaraEngine>) {
    let root = match fs::canonicalize(path) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("[ERROR] Cannot access target: {error}");
            return;
        }
    };

    let mut files: Vec<PathBuf> = Vec::new();
    let mut discovery_errors = 0usize;

    println!("[+] Discovering accessible files...");

    let walker = WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            let path = entry.path();

            if entry.depth() == 0 {
                return true;
            }

            ![
                "/proc",
                "/sys",
                "/dev",
            ]
            .iter()
            .any(|excluded| path == Path::new(excluded))
        });

    for entry in walker {
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                files.push(entry.path().to_path_buf());
            }
            Ok(_) => {}
            Err(error) => {
                discovery_errors += 1;
                eprintln!("[ACCESS ERROR] {error}");
            }
        }
    }

    let total = files.len();
    let mut scanned = 0usize;
    let mut scan_errors = 0usize;

    let mut suspicious = Vec::new();
    let mut malicious = Vec::new();
    let mut yara_detections: Vec<(PathBuf, Vec<String>)> = Vec::new();

    println!("[+] Found {total} accessible files.");
    println!("[+] Starting scan...\n");

    for file in &files {
        match verify_file(file) {
            Ok(report) => {
                scanned += 1;

                match report.verdict {
                    Verdict::Suspicious => suspicious.push(file.clone()),
                    Verdict::ConfirmedMalicious => malicious.push(file.clone()),
                    Verdict::NoKnownThreats => {}
                }
            }
            Err(error) => {
                scan_errors += 1;
                eprintln!("\n[SCAN ERROR] {}: {error}", file.display());
            }
        }

        if let Some(engine) = yara {
            match engine.scan_file(file) {
                Ok(matches) if !matches.is_empty() => {
                    yara_detections.push((file.clone(), matches));
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("\n[YARA ERROR] {}: {error}", file.display());
                }
            }
        }

        let completed = scanned + scan_errors;
        let percent = if total == 0 {
            100
        } else {
            completed * 100 / total
        };

        let filled = percent * 30 / 100;

        print!(
            "\r[{}{}] {}% ({}/{})",
            "#".repeat(filled),
            "-".repeat(30 - filled),
            percent,
            completed,
            total
        );

        let _ = io::stdout().flush();
    }

    println!("\n\n================================");
    println!("          Scan Completed");
    println!("================================");

    println!("\n[SUMMARY]");
    println!("Files discovered: {total}");
    println!("Files scanned: {scanned}");
    println!("Scan errors: {scan_errors}");
    println!("Discovery errors: {discovery_errors}");
    println!("Suspicious: {}", suspicious.len());
    println!("Malicious: {}", malicious.len());
    println!("YARA matches: {}", yara_detections.len());

    for (file, matches) in &yara_detections {
        println!("\n[YARA DETECTION] {}", file.display());

        for rule in matches {
            println!("  Rule: {rule}");
        }
    }

    println!("\n[!] YARA matches are rule matches, not automatic proof of malware.");
}
