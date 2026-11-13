
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use walkdir::WalkDir;

const BUFFER_SIZE: usize = 64 * 1024;

pub struct ScanReport {
    pub files_scanned: usize,
    pub errors: usize,
}

fn calculate_hash(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

pub fn scan_directory(path: &Path) -> ScanReport {
    let mut report = ScanReport {
        files_scanned: 0,
        errors: 0,
    };

    println!("\n========== PSCANAV ==========");
    println!("Scanning directory...\n");

    for entry in WalkDir::new(path).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                report.errors += 1;
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        match calculate_hash(entry.path()) {
            Ok(_hash) => {
                report.files_scanned += 1;
            }
            Err(_) => {
                report.errors += 1;
            }
        }
    }

    println!("========== RESULTS ==========");
    println!("Files scanned: {}", report.files_scanned);
    println!("Errors: {}", report.errors);
    println!("=============================");

    report
}
