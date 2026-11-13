
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

const BUFFER_SIZE: usize = 64 * 1024;

// Only add hashes from trusted threat-intelligence sources.
const KNOWN_BAD_SHA256: &[&str] = &[];

// Harmless standardized antivirus test signature.
const EICAR_SIGNATURE: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    NoKnownThreats,
    ConfirmedMalicious,
}

pub struct VerificationReport {
    pub sha256: String,
    pub file_type: &'static str,
    pub verdict: Verdict,
    pub findings: Vec<String>,
}

pub fn verify_file(path: &Path) -> io::Result<VerificationReport> {
    let metadata = fs::symlink_metadata(path)?;

    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Only regular files can be scanned.",
        ));
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut header = Vec::new();

    // Preserve enough trailing bytes to detect signatures
    // split across consecutive read buffers.
    let mut carry = Vec::new();
    let mut eicar_detected = false;

    loop {
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];
        hasher.update(chunk);

        if header.len() < 16 {
            let remaining = 16 - header.len();
            header.extend_from_slice(&chunk[..remaining.min(bytes_read)]);
        }

        if !eicar_detected {
            let mut combined = Vec::with_capacity(carry.len() + bytes_read);
            combined.extend_from_slice(&carry);
            combined.extend_from_slice(chunk);

            if combined
                .windows(EICAR_SIGNATURE.len())
                .any(|window| window == EICAR_SIGNATURE)
            {
                eicar_detected = true;
            }

            let keep = combined.len().min(EICAR_SIGNATURE.len() - 1);
            carry = combined[combined.len() - keep..].to_vec();
        }
    }

    let sha256 = hex::encode(hasher.finalize());
    let file_type = identify_file_type(&header);

    let known_bad = KNOWN_BAD_SHA256
        .iter()
        .any(|known| *known == sha256.as_str());

    let mut findings = Vec::new();

    let verdict = if eicar_detected {
        findings.push("EICAR antivirus test signature detected.".into());
        Verdict::ConfirmedMalicious
    } else if known_bad {
        findings.push("Exact SHA-256 match in trusted local threat list.".into());
        Verdict::ConfirmedMalicious
    } else {
        Verdict::NoKnownThreats
    };

    findings.push(format!("File type: {file_type}"));
    findings.push(format!("File size: {} bytes", metadata.len()));
    findings.push(format!("SHA-256: {sha256}"));

    Ok(VerificationReport {
        sha256,
        file_type,
        verdict,
        findings,
    })
}

// Keep your existing identify_file_type implementation below.
// Keep any other existing helper functions required by your project.
