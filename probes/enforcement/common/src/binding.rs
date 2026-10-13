//! The W06 host binding: run facts only (the W06 route and the loaded policy's digest, the bound execution's signed
//! expiry and identifier, which peer to kill), never expected results and never paths (the role cgroup paths are
//! contract constants in `expected.rs`). One `key=value` per line; blank lines and `#` comments are skipped. Each case names its closed key set:
//! a missing, unknown or repeated key, or a malformed line, refuses the binding.
use std::collections::BTreeMap;
use std::io;

pub struct Binding {
    values: BTreeMap<String, String>,
}

impl Binding {
    pub fn load(path: &str, keys: &[&str]) -> Result<Binding, String> {
        let text = crate::read::text(path).map_err(|error| format!("binding unreadable: {}", error))?;
        let mut values = BTreeMap::new();
        for (number, line) in text.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| format!("binding line {} is not key=value", number + 1))?;
            if !keys.contains(&key) {
                return Err(format!("binding key {} is not one of this case's keys", key));
            }
            if value.is_empty() || value.trim() != value {
                return Err(format!("binding key {} has an empty or padded value", key));
            }
            if values.insert(key.to_string(), value.to_string()).is_some() {
                return Err(format!("binding key {} repeated", key));
            }
        }
        if let Some(missing) = keys.iter().find(|key| !values.contains_key(**key)) {
            return Err(format!("binding key {} missing", missing));
        }
        Ok(Binding { values })
    }

    pub fn get(&self, key: &str) -> &str {
        &self.values[key]
    }

    /// Every pair, in key order, for the report.
    pub fn pairs(&self) -> Vec<(String, String)> {
        self.values.iter().map(|(key, value)| (key.clone(), value.clone())).collect()
    }
}

/// io::Error → the text a report records (with the errno when there is one).
pub fn describe(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(errno) => format!("{} (errno {})", error, errno),
        None => error.to_string(),
    }
}
