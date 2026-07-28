pub mod engine;

use std::fs;
use std::path::Path;

/// Reads rules from a file, skipping blank lines and comments.
pub fn load_rules(path: &str) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(Path::new(path))
        .map_err(|e| format!("Failed to read rules file: {}", e))?;

    let rules: Vec<String> = content.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .collect();

    if rules.is_empty() {
        return Err("No valid rules found".to_string());
    }

    Ok(rules)
}
