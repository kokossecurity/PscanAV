
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

const BUFFER_SIZE: usize = 64 * 1024;

// Only add hashes from trusted threat-intelligence sources.
const KNOWN_BAD_SHA256: &[&str] = &[];

const INDICATORS: &[(&[u8], &str)] = &[
    (b"ptrace", "References process tracing"),
    (b"memfd_create", "References anonymous memory files"),
    (b"ld_preload", "References dynamic-loader overrides"),
    (b"base64 -d", "Contains an encoded-data decoding command"),
    (b"bash -c", "References shell command execution"),
    (b"chmod +x", "References executable permission changes"),
    (b"mkfifo", "References named-pipe creation"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    let mut byte_counts = [0u64; 256];
    let mut total_bytes = 0u64;
    let mut header = Vec::new();

    let max_marker_len = INDICATORS
        .iter()
        .map(|(marker, _)| marker.len())
        .max()
        .unwrap_or(1);

    let mut carry = Vec::new();
    let mut indicator_hits = vec![false; INDICATORS.len()];

    loop {
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];

        hasher.update(chunk);
        total_bytes += bytes_read as u64;

        for &byte in chunk {
            byte_counts[byte as usize] += 1;
        }

        if header.len() < 16 {
            let remaining = 16 - header.len();
            header.extend_from_slice(&chunk[..remaining.min(bytes_read)]);
        }

        let mut combined = Vec::with_capacity(carry.len() + bytes_read);
        combined.extend_from_slice(&carry);
        combined.extend_from_slice(chunk);

        let lowercase: Vec<u8> = combined
            .iter()
            .map(|byte| byte.to_ascii_lowercase())
            .collect();

        for (index, (marker, _)) in INDICATORS.iter().enumerate() {
            if !indicator_hits[index]
                && lowercase.windows(marker.len()).any(|w| w == *marker)
            {
                indicator_hits[index] = true;
            }
        }

        let keep = combined.len().min(max_marker_len.saturating_sub(1));
        carry = combined[combined.len() - keep..].to_vec();
    }

    let sha256 = hex::encode(hasher.finalize());
    let file_type = identify_file_type(&header);

    let mut findings = Vec::new();
    let mut indicator_score = 0u8;

    for (index, (_, description)) in INDICATORS.iter().enumerate() {
        if indicator_hits[index] {
            findings.push(description.to_string());
            indicator_score += 1;
        }
    }

    // Entropy is informational only. Compressed files naturally have
    // high entropy, so it must not independently increase suspicion.
    let mut entropy = 0.0;

    if total_bytes > 0 {
        for count in byte_counts {
            if count > 0 {
                let probability = count as f64 / total_bytes as f64;
                entropy -= probability * probability.log2();
            }
        }
    }

    if total_bytes >= 16 * 1024 && entropy >= 7.5 {
        findings.push(format!(
            "High entropy ({:.2}/8.0); compression or encryption may explain this.",
            entropy
        ));
    }

    // Extension mismatches are warnings, not malware evidence.
    if let Some(message) = extension_mismatch(path, file_type) {
        findings.push(message);
    }

    let known_bad = KNOWN_BAD_SHA256
        .iter()
        .any(|known| *known == sha256.as_str());

    // Generic strings are weak indicators. Require multiple indicators
    // before assigning a suspicious verdict.
    let verdict = if known_bad {
        findings.push(
            "Exact SHA-256 match in the trusted local threat list.".into(),
        );
        Verdict::ConfirmedMalicious
    } else if indicator_score >= 3 {
        Verdict::Suspicious
    } else {
        Verdict::NoKnownThreats
    };

    findings.push(format!("Detected format: {}", file_type));
    findings.push(format!("File size: {} bytes", total_bytes));
    findings.push(format!("Entropy: {:.2}/8.0", entropy));
    findings.push(format!("SHA-256: {}", sha256));

    Ok(VerificationReport {
        sha256,
        file_type,
        verdict,
        findings,
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
    } else if data.starts_with(b"\x89PNG\r\n\x1A\n") {
        "PNG image"
    } else if data.starts_with(b"\xFF\xD8\xFF") {
        "JPEG image"
    } else if data.len() >= 12
        && &data[0..4] == b"RIFF"
        && &data[8..12] == b"WEBP"
    {
        "WebP image"
    } else if data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
    {
        "GIF image"
    } else if data.starts_with(b"BM") {
        "BMP image"
    } else {
        "Unknown or text format"
    }
}

fn extension_mismatch(
    path: &Path,
    file_type: &str,
) -> Option<String> {
    let extension = path
        .extension()?
        .to_str()?
        .to_ascii_lowercase();

    let mismatch = match file_type {
        "ELF executable" => {
            !["elf", "so", "bin"].contains(&extension.as_str())
        }
        "Windows executable" => {
            !["exe", "dll", "sys"].contains(&extension.as_str())
        }
        "PDF document" => extension != "pdf",
        "ZIP archive" => {
            !["zip", "jar", "apk", "docx", "xlsx", "pptx"]
                .contains(&extension.as_str())
        }
        "PNG image" => extension != "png",
        "JPEG image" => {
            !["jpg", "jpeg"].contains(&extension.as_str())
        }
        "WebP image" => extension != "webp",
        "GIF image" => extension != "gif",
        "BMP image" => extension != "bmp",
        _ => false,
    };

    if mismatch {
        Some(format!(
            "File extension .{} does not match detected format {}.",
            extension, file_type
        ))
    } else {
        None
    }
}
