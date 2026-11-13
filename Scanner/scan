
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
    println!("Scanning: {}\n", path.display());

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("[ERROR] {}", error);
                report.errors += 1;
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let file_path = entry.path();

        match calculate_hash(file_path) {
            Ok(hash) => {
                report.files_scanned += 1;

                println!("[SCANNED] {}", file_path.display());
                println!("SHA256: {}\n", hash);
            }

            Err(error) => {
                report.errors += 1;

                eprintln!(
                    "[ERROR] {}: {}",
                    file_path.display(),
                    error
                );
            }
        }
    }

    println!("========== RESULTS ==========");
    println!("Files scanned: {}", report.files_scanned);
    println!("Errors: {}", report.errors);

    report
}
