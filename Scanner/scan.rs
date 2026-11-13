
use crate::verifier::{verify_file, Verdict};
use crate::yara::YaraEngine;

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use walkdir::{DirEntry, WalkDir};

fn should_skip_directory(entry: &DirEntry) -> bool {
    const EXCLUDED: &[&str] = &[
        "/proc",
        "/sys",
        "/dev",
        "/acct",
        "/apex",
    ];

    let path = entry.path();

    EXCLUDED.iter().any(|excluded| {
        let excluded = Path::new(excluded);
        path == excluded || path.starts_with(excluded)
    })
}

fn is_yara_rule_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("yar" | "yara")
    )
}

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
    println!("[+] Target: {}", root.display());

    let walker = WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0 || !should_skip_directory(entry)
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

    let mut processed = 0usize;
    let mut scanned = 0usize;
    let mut scan_errors = 0usize;
    let mut yara_errors = 0usize;

    let mut suspicious = Vec::new();
    let mut malicious = Vec::new();
    let mut yara_detections: Vec<(PathBuf, Vec<String>)> = Vec::new();

    println!("\n[+] Discovered {total} accessible files.");
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
                eprintln!(
                    "\n[SCAN ERROR] {}: {error}",
                    file.display()
                );
            }
        }

        // Do not scan YARA rule source files with YARA itself.
        if let Some(engine) = yara {
            if !is_yara_rule_file(file) {
                match engine.scan_file(file) {
                    Ok(matches) if !matches.is_empty() => {
                        yara_detections.push((file.clone(), matches));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        yara_errors += 1;
                        eprintln!(
                            "\n[YARA ERROR] {}: {error}",
                            file.display()
                        );
                    }
                }
            }
        }

        processed += 1;

        let percent = if total == 0 {
            100
        } else {
            processed * 100 / total
        };

        let filled = percent * 30 / 100;

        print!(
            "\r[{}{}] {}% ({}/{})",
            "#".repeat(filled),
            "-".repeat(30 - filled),
            percent,
            processed,
            total
        );

        let _ = io::stdout().flush();
    }

    println!("\n\n================================");
    println!("          Scan Completed");
    println!("================================");

    println!("\n[SUMMARY]");
    println!("Files discovered: {total}");
    println!("Files processed: {processed}");
    println!("Files scanned: {scanned}");
    println!("Discovery errors: {discovery_errors}");
    println!("Scan errors: {scan_errors}");
    println!("YARA errors: {yara_errors}");
    println!("Suspicious: {}", suspicious.len());
    println!("Malicious: {}", malicious.len());
    println!("Files with YARA matches: {}", yara_detections.len());

    for file in &suspicious {
        println!("\n[SUSPICIOUS] {}", file.display());
    }

    for file in &malicious {
        println!("\n[MALICIOUS] {}", file.display());
    }

    for (file, matches) in &yara_detections {
        println!("\n[YARA DETECTION] {}", file.display());

        for rule in matches {
            println!("  Rule: {rule}");
        }
    }

    println!(
        "\n[!] YARA matches are rule matches, not automatic proof of malware."
    );
    println!("[!] Inaccessible paths were skipped.");
}
