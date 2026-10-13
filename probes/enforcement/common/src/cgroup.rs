//! cgroup v2 reads: `cgroup.events` and `cgroup.procs` (the TG-05 probes write no cgroup file).
use crate::read;
use std::io;
use std::path::Path;

/// `populated` and `frozen` from `cgroup.events` (Documentation/admin-guide/cgroup-v2.rst).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Events {
    pub populated: bool,
    pub frozen: bool,
}

pub fn events(cgroup: &Path) -> io::Result<Events> {
    let text = read::text(&cgroup.join("cgroup.events").to_string_lossy())?;
    let (mut populated, mut frozen) = (None, None);
    for line in text.lines() {
        match line.split_once(' ') {
            Some(("populated", value)) => populated = Some(flag(value)?),
            Some(("frozen", value)) => frozen = Some(flag(value)?),
            _ => {}
        }
    }
    match (populated, frozen) {
        (Some(populated), Some(frozen)) => Ok(Events { populated, frozen }),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "cgroup.events without populated and frozen")),
    }
}

/// The process IDs in `cgroup.procs`, in file order.
pub fn procs(cgroup: &Path) -> io::Result<Vec<i32>> {
    let text = read::text(&cgroup.join("cgroup.procs").to_string_lossy())?;
    text.lines().map(|line| line.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cgroup.procs"))).collect()
}

fn flag(value: &str) -> io::Result<bool> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "cgroup.events flag")),
    }
}
