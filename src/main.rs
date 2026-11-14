
#[path = "../verifier/verifier.rs"]
mod verifier;

#[path = "../Scanner/scan.rs"]
mod file_scanner;

#[path = "../engines/yara.rs"]
mod yara;

#[path = "../engines/clamav.rs"]
mod clamav;

use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use verifier::Verdict;

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

    let clamav_engine = match clamav::ClamAvEngine::new() {
        Ok(engine) => Some(engine),
        Err(error) => {
            eprintln!("[!] ClamAV unavailable: {error}");
            None
        }
    };

    // Each path stores the engines that flagged it.
    let mut candidates: BTreeMap<PathBuf, Vec<String>> =
        BTreeMap::new();

    let mut total_files_discovered = 0usize;
    let mut total_discovery_errors = 0usize;
    let mut total_yara_errors = 0usize;
    let mut clamav_detections = 0usize;
    let mut yara_detections = 0usize;

    // STAGE 1: SCANNING
    println!("\n================================");
    println!("             SCANNING");
    println!("================================");

    for target in &args {
        let path = Path::new(target);

        if !path.is_dir() {
            eprintln!("[ERROR] Invalid directory: {}", path.display());
            continue;
        }

        println!("\n[+] Target: {}", path.display());

        // ClamAV scan
        if let Some(engine) = &clamav_engine {
            match engine.scan_directory(path) {
                Ok(detections) => {
                    clamav_detections += detections.len();

                    for detection in detections {
                        candidates
                            .entry(detection.path)
                            .or_default()
                            .push(format!(
                                "ClamAV: {}",
                                detection.signature
                            ));
                    }
                }
                Err(error) => {
                    eprintln!("[CLAMAV ERROR] {error}");
                }
            }
        }

        // YARA scan
        let results =
            file_scanner::scan_directory(path, yara_engine.as_ref());

        total_files_discovered += results.files_discovered;
        total_discovery_errors += results.discovery_errors;
        total_yara_errors += results.yara_errors;

        for (file, rules) in results.yara_detections {
            yara_detections += 1;

            let findings = candidates.entry(file).or_default();

            for rule in rules {
                findings.push(format!("YARA: {rule}"));
            }
        }
    }

    // STAGE 2: VERIFICATION
    println!("\n================================");
    println!("           VERIFICATION");
    println!("================================");

    println!(
        "[+] Files requiring verification: {}",
        candidates.len()
    );

    let mut verified = 0usize;
    let mut verification_errors = 0usize;
    let mut verifier_matches = 0usize;

    for (file, engine_findings) in &candidates {
        println!("\n[VERIFYING] {}", file.display());

        for finding in engine_findings {
            println!("  Engine finding: {finding}");
        }

        match verifier::verify_file(file) {
            Ok(report) => {
                verified += 1;

                println!("  File type: {}", report.file_type);
                println!("  SHA-256: {}", report.sha256);

                if report.verdict == Verdict::ConfirmedMalicious {
                    verifier_matches += 1;
                    println!("  [VERIFIER MATCH]");
                } else {
                    println!("  [NO LOCAL VERIFIER MATCH]");
                }

                for finding in &report.findings {
                    println!("  Info: {finding}");
                }
            }
            Err(error) => {
                verification_errors += 1;
                eprintln!(
                    "  [VERIFICATION ERROR] {}: {error}",
                    file.display()
                );
            }
        }
    }

    // FINAL SUMMARY
    println!("\n================================");
    println!("          FINAL SUMMARY");
    println!("================================");

    println!("\n[SCANNING]");
    println!("Files discovered: {total_files_discovered}");
    println!("Discovery errors: {total_discovery_errors}");
    println!("ClamAV detections: {clamav_detections}");
    println!("YARA detections: {yara_detections}");
    println!("YARA errors: {total_yara_errors}");

    println!("\n[VERIFICATION]");
    println!("Files verified: {verified}");
    println!("Verification errors: {verification_errors}");
    println!("Local verifier matches: {verifier_matches}");

    println!("\n[!] A local verifier match does not replace engine findings.");
    println!("[!] A missing local match does not mean a file is safe.");
    println!("[!] YARA matches are not automatic proof of malware.");

    println!("\n[+] PscanAV finished.");
}
