
use std::{
    io,
    path::Path,
    process::Command,
};

pub struct YaraEngine {
    rules_directory: std::path::PathBuf,
}

impl YaraEngine {
    pub fn new(rules_directory: &Path) -> io::Result<Self> {
        if !rules_directory.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "YARA rules directory not found",
            ));
        }

        if Command::new("yara")
            .arg("--version")
            .output()
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "YARA executable not found. Install it with pkg install yara.",
            ));
        }

        Ok(Self {
            rules_directory: rules_directory.to_path_buf(),
        })
    }

    pub fn scan_file(&self, file_path: &Path) -> io::Result<Vec<String>> {
        let mut detections = Vec::new();

        let entries = std::fs::read_dir(&self.rules_directory)?;

        for entry in entries {
            let entry = entry?;
            let rule_path = entry.path();

            let extension = rule_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("");

            if !matches!(extension, "yar" | "yara") {
                continue;
            }

            let output = Command::new("yara")
                .arg("-w")
                .arg(&rule_path)
                .arg(file_path)
                .output()?;

            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                if let Some(rule_name) = line.split_whitespace().next() {
                    detections.push(rule_name.to_string());
                }
            }
        }

        Ok(detections)
    }
}
