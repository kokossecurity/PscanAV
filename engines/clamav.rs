
use std::{
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
            return Err(io::Error::other(
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

        let mut child = Command::new(&self.executable)
            .arg("--recursive")
            .arg("--infected")
            .arg("--show-progress")
            .arg("--cross-fs=no")
            .arg("--exclude-dir=^/proc(/|$)")
            .arg("--exclude-dir=^/sys(/|$)")
            .arg("--exclude-dir=^/dev(/|$)")
            .arg("--exclude-dir=^/acct(/|$)")
            .arg("--exclude-dir=^/apex(/|$)")
            .arg(directory)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::other("Could not capture ClamAV output.")
        })?;

        let reader = BufReader::new(stdout);
        let mut detections = Vec::new();

        for line in reader.lines() {
            let line = line?;

            if let Some((path, result)) = line.rsplit_once(": ") {
                if let Some(signature) = result.strip_suffix(" FOUND") {
                    detections.push(ClamAvDetection {
                        path: PathBuf::from(path),
                        signature: signature.to_string(),
                    });

                    println!("\n[CLAMAV DETECTION] {}", path);
                    println!("  Signature: {}", signature);
                } else {
                    println!("{line}");
                }
            } else if !line.trim().is_empty() {
                println!("{line}");
            }
        }

        let status = child.wait()?;

        println!("\n================================");
        println!("       CLAMAV SCAN COMPLETE");
        println!("================================");
        println!("Detections: {}", detections.len());

        match status.code() {
            Some(0) | Some(1) => Ok(detections),
            code => Err(io::Error::other(
                format!("ClamAV exited with status {code:?}"),
            )),
        }
    }
}
