use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const BUFFER_SIZE: usize = 64 * 1024;
const SAMPLE_LIMIT: usize = 4 * 1024 * 1024;

// Add only verified SHA-256 hashes from trusted threat-intelligence sources.
// Empty by default: no files will be quarantined based on an unverified guess.
const KNOWN_BAD_SHA256: &[&str] = &[];

const INDICATORS: &[(&[u8], &str)] = &[
    (b"ptrace", "References process-tracing functionality"),
    (b"memfd_create", "References anonymous in-memory files"),
    (b"LD_PRELOAD", "References dynamic-loader overrides"),
    (b"base64 -d", "Contains an encoded-data decoding command"),
    (b"bash -c", "References shell command execution"),
    (b"chmod +x", "References executable permission changes"),
    (b"mkfifo", "References named-pipe creation"),
];

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    NoKnownThreats,
    Suspicious,
    ConfirmedMalicious,
}

pub struct VerificationReport {
    pub sha256: String,
    pub file_type: &'static str,
    pub verdict: Verdict,
    pub findings: Vec<String>,
    pub quarantined_to: Option<PathBuf>,
}

pub fn verify_file(
    path: &Path,
    quarantine_dir: &Path,
) -> io::Result<VerificationReport> {
    let metadata = fs::symlink_metadata(path)?;

    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Only regular files can be verified.",
        ));
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut sample = Vec::new();
    let mut byte_counts = [0u64; 256];
    let mut total_bytes = 0u64;

    // Hash the entire file and collect a limited sample for analysis.
    loop {
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];
        hasher.update(chunk);
        total_bytes = total_bytes.saturating_add(bytes_read as u64);

        for &byte in chunk {
            byte_counts[byte as usize] += 1;
        }

        let remaining = SAMPLE_LIMIT.saturating_sub(sample.len());
        let copy_length = remaining.min(bytes_read);

        sample.extend_from_slice(&chunk[..copy_length]);
    }

    let sha256 = hex::encode(hasher.finalize());
    let file_type = identify_file_type(&sample);

    let sample_lower: Vec<u8> = sample
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect();

    let mut findings = Vec::new();
    let mut score = 0u8;

    // Look for static indicators. These are clues, not proof of malware.
    for (marker, description) in INDICATORS {
        let marker_lower: Vec<u8> = marker
            .iter()
            .map(|byte| byte.to_ascii_lowercase())
            .collect();

        if sample_lower
            .windows(marker_lower.len())
            .any(|window| window == marker_lower.as_slice())
        {
            findings.push(description.to_string());
            score += 1;
        }
    }

    // Calculate Shannon entropy across the entire file.
    let mut entropy = 0.0;

    if total_bytes > 0 {
        for count in byte_counts {
            if count > 0 {
                let probability = count as f64 / total_bytes as f64;
                entropy -= probability * probability.log2();
            }
        }
    }

    // High entropy is only a weak indicator; compressed files can also have it.
    if total_bytes >= 16 * 1024 && entropy >= 7.5 {
        findings.push(format!(
            "High file entropy detected ({:.2}/8.0)",
            entropy
        ));
        score += 1;
    }

    findings.push(format!("File format: {}", file_type));
    findings.push(format!("File size: {} bytes", total_bytes));
    findings.push(format!("SHA-256: {}", sha256));

    let known_bad = KNOWN_BAD_SHA256
        .iter()
        .any(|known_hash| *known_hash == sha256.as_str());

    let verdict = if known_bad {
        findings.push("Exact match in the trusted local threat list.".into());
        Verdict::ConfirmedMalicious
    } else if score >= 3 {
        Verdict::Suspicious
    } else {
        Verdict::NoKnownThreats
    };

    // Automatic quarantine is reserved for exact trusted hash matches.
    let mut quarantined_to = None;

    if verdict == Verdict::ConfirmedMalicious {
        match quarantine_file(path, quarantine_dir, &sha256) {
            Ok(destination) => {
                findings.push("File successfully quarantined.".into());
                quarantined_to = Some(destination);
            }
            Err(error) => {
                findings.push(format!(
                    "QUARANTINE FAILED: {}",
                    error
                ));
            }
        }
    }

    Ok(VerificationReport {
        sha256,
        file_type,
        verdict,
        findings,
        quarantined_to,
    })
}

fn identify_file_type(data: &[u8]) -> &'static str {
    if data.starts_with(b"\x7FELF") {
        "ELF executable"
    } else if data.starts_with(b"MZ") {
        "Windows executable"
    } else if data.starts_with(b"%PDF") {
        "PDF document"
    } else if data.starts_with(b"PK\x03\x04") {
        "ZIP archive"
    } else {
        "Unknown or text format"
    }
}

fn sha256_file(path: &Path) -> io::Result<String> {
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

fn quarantine_file(
    source_path: &Path,
    quarantine_dir: &Path,
    expected_hash: &str,
) -> io::Result<PathBuf> {
    let source = fs::canonicalize(source_path)?;

    if !fs::symlink_metadata(&source)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Source is not a regular file.",
        ));
    }

    // Check again immediately before moving the file.
    if sha256_file(&source)? != expected_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File contents changed during verification.",
        ));
    }

    fs::create_dir_all(quarantine_dir)?;

    let directory_metadata = fs::symlink_metadata(quarantine_dir)?;

    if directory_metadata.file_type().is_symlink()
        || !directory_metadata.is_dir()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Quarantine destination must be a real directory.",
        ));
    }

    // Restrict access to the quarantine directory on Linux.
    #[cfg(unix)]
    fs::set_permissions(
        quarantine_dir,
        fs::Permissions::from_mode(0o700),
    )?;

    let quarantine_dir = fs::canonicalize(quarantine_dir)?;

    if source.starts_with(&quarantine_dir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "File is already inside quarantine.",
        ));
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..1000 {
        let filename = format!(
            "{}.{}.{}.{}.quarantined",
            expected_hash,
            timestamp,
            std::process::id(),
            attempt
        );

        let destination = quarantine_dir.join(filename);

        match fs::symlink_metadata(&destination) {
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        fs::rename(&source, &destination)?;

        // Remove executable permissions and restrict file access.
        #[cfg(unix)]
        if let Err(error) = fs::set_permissions(
            &destination,
            fs::Permissions::from_mode(0o600),
        ) {
            let _ = fs::rename(&destination, &source);
            return Err(error);
        }

        // Confirm that the moved file still has the expected hash.
        match sha256_file(&destination) {
            Ok(moved_hash) if moved_hash == expected_hash => {
                return Ok(destination);
            }
            _ => {
                let _ = fs::rename(&destination, &source);

                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Quarantined file failed hash verification.",
                ));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Could not find a unique quarantine filename.",
    ))
             }
