
use std::{
    error::Error,
    fs,
    io,
    path::Path,
};

use yara_x::{Compiler, Rules, Scanner};

pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    pub fn new(rules_directory: &Path) -> Result<Self, Box<dyn Error>> {
        let mut compiler = Compiler::new();
        let mut rule_sources = Vec::new();

        let mut entries = fs::read_dir(rules_directory)?
            .collect::<Result<Vec<_>, _>>()?;

        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let path = entry.path();

            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("");

            if !matches!(extension, "yar" | "yara") {
                continue;
            }

            let source = fs::read_to_string(&path)?;
            rule_sources.push(source);
        }

        if rule_sources.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No YARA rules found.",
            ).into());
        }

        for source in &rule_sources {
            compiler.add_source(source.as_str())?;
        }

        let rules = compiler.build();

        Ok(Self { rules })
    }

    pub fn scan_file(
        &self,
        file_path: &Path,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let mut scanner = Scanner::new(&self.rules);

        let results = scanner.scan_file(file_path)?;

        let detections = results
            .matching_rules()
            .map(|rule| rule.identifier().to_string())
            .collect();

        Ok(detections)
    }
}
