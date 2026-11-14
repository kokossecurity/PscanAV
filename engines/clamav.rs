
use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use walkdir::{DirEntry, WalkDir};

pub struct ClamAvDetection {
    pub path: PathBuf,
    pub signature: String,
}

pub struct ClamAvEngine {
    executable: String,
}

fn should_visit(entry: &DirEntry) -> bool {
    let path = entry.path();

    ![
        Path::new("/proc"),
        Path::new("/sys"),
        Path::new("/dev"),
        Path::new("/acct"),
        Path::new("/apex"),
    ]
    .iter()
    .any(|excluded| path == *excluded)
}

fn print_progress(done: usize, total: usize) {
    let width = 35;
    let percent = if total == 0 {
        100
    } else {
        done.saturating_mul(100) / total
    };

    let filled = percent * width / 100;
    let bar = format!(
        "{}{}",
        "#".repeat(filled),
        "-".repeat(width - filled)
    );

    print!(
        "\rClamAV [{bar}] {percent:3}% ({done}/{total})"
    );

    let _ = io::stdout().flush();
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
        println!("[+] Collecting files for ClamAV...");

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let list_path = std::env::temp_dir().join(format!(
            "pscanav-clamav-{}-{timestamp}.list",
            std::process::id()
        ));

        let list_file = File::create(&list_path)?;
        let mut writer = BufWriter::new(list_file);

        let mut total = 0usize;

        for entry in WalkDir::new(directory)
            .follow_links(false)
            .into_iter()
            .filter_entry(should_visit)
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            if entry.file_type().is_file() {
                writer.write_all(entry.path().as_os_str().as_bytes())?;
                writer.write_all(b"\n")?;
                total += 1;
            }
        }

        writer.flush()?;
        drop(writer);

        println!("[+] Files queued for ClamAV: {total}");

        if total == 0 {
            let _ = std::fs::remove_file(&list_path);
            println!("[+] No files to scan.");
            return Ok(Vec::new());
        }

        println!("[+] ClamAV scanning: {}", directory.display());

        let mut child = Command::new(&self.executable)
            .arg("--verbose")
            .arg("--no-summary")
            .arg(format!("--file-list={}", list_path.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::other("Could not capture ClamAV output.")
        })?;

        let reader = BufReader::new(stdout);
        let mut detections = Vec::new();
        let mut processed = 0usize;

        print_progress(0, total);

        for line in reader.lines() {
            let line = line?;

            let Some((path, result)) = line.rsplit_once(": ") else {
                continue;
            };

            let signature = if let Some(signature) =
                result.strip_suffix(" FOUND")
            {
                Some(signature.to_string())
            } else if result == "OK" {
                None
            } else {
                continue;
            };

            processed += 1;
            print_progress(processed, total);

            if let Some(signature) = signature {
                println!();
                println!("[CLAMAV DETECTION] {path}");
                println!("  Signature: {signature}");

                detections.push(ClamAvDetection {
                    path: PathBuf::from(path),
                    signature,
                });

                print_progress(processed, total);
            }
        }

        let status = child.wait()?;
        let _ = std::fs::remove_file(&list_path);

        println!();
        println!("================================");
        println!("       Scan Completed");
        println!("================================");
        println!("Files processed: {processed}/{total}");
        println!("Detections: {}", detections.len());

        match status.code() {
            Some(0) | Some(1) => Ok(detections),
            code => Err(io::Error::other(format!(
                "ClamAV exited with status {code:?}"
            ))),
        }
    }
}
