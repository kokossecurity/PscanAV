
use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

pub struct ClamAvDetection {
    pub path: PathBuf,
    pub signature: String,
}

pub struct ClamAvEngine {
    executable: String,
}

impl ClamAvEngine {
    pub fn new() -> io::Result<Self> {
        let executable = "clamscan".to_string();

        let output = Command::new(&executable)
            .arg("--version")
            .output()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("ClamAV unavailable: {error}"),
                )
            })?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Could not initialize ClamAV.",
            ));
        }

        println!(
            "[+] ClamAV initialized: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );

        Ok(Self { executable })
    }

    pub fn scan_directory(
        &self,
        directory: &Path,
    ) -> io::Result<Vec<ClamAvDetection>> {
        println!("[+] ClamAV scanning: {}", directory.display());

        let output = Command::new(&self.executable)
            .arg("--recursive")
            .arg("--infected")
            .arg("--no-summary")
            .arg("--cross-fs=no")
            .arg("--exclude-dir=^/proc(/|$)")
            .arg("--exclude-dir=^/sys(/|$)")
            .arg("--exclude-dir=^/dev(/|$)")
            .arg("--exclude-dir=^/acct(/|$)")
            .arg("--exclude-dir=^/apex(/|$)")
            .arg(directory)
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut detections = Vec::new();

        for line in stdout.lines().chain(stderr.lines()) {
            let Some((path, result)) = line.rsplit_once(": ") else {
                continue;
            };

            let Some(signature) = result.strip_suffix(" FOUND") else {
                continue;
            };

            detections.push(ClamAvDetection {
                path: PathBuf::from(path),
                signature: signature.to_string(),
            });
        }

        match output.status.code() {
            Some(0) | Some(1) => Ok(detections),
            code => {
                let details = if stderr.trim().is_empty() {
                    format!("clamscan exited with status {code:?}")
                } else {
                    stderr.trim().to_string()
                };

                Err(io::Error::new(
                    io::ErrorKind::Other,
                    details,
                ))
            }
        }
    }
}
