//! Small reads of /proc, /sys and cgroup files: open, then read in fixed chunks. No fstat or seek, so the only SELinux
//! checks a read makes are the path walk's `search`, `open` and `read`.
use std::fs::File;
use std::io::{self, Read};

const LIMIT: usize = 1 << 20;

pub fn text(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > LIMIT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file larger than the probe reads"));
        }
    }
    String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))
}
