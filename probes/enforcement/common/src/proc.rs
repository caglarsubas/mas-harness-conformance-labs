//! /proc reads: a process's state, parent, user time and start time, and the boot ID.
use crate::read;
use std::io;

/// Fields of /proc/<pid>/stat after the command name (proc(5); the name is skipped at its last ')').
#[derive(Clone, Debug, PartialEq)]
pub struct Stat {
    pub state: char,
    pub ppid: i32,
    pub utime_ticks: u64,
    pub start_ticks: u64,
}

pub fn stat(pid: i32) -> io::Result<Stat> {
    let text = read::text(&format!("/proc/{}/stat", pid))?;
    let after = text.rfind(')').map(|at| &text[at + 1..]).ok_or_else(|| invalid("stat without a command name"))?;
    let fields: Vec<&str> = after.split_ascii_whitespace().collect();
    // After the name: state(3) ppid(4) ... utime(14) ... starttime(22), numbered as in proc(5).
    if fields.len() < 20 {
        return Err(invalid("short stat"));
    }
    let number = |index: usize| -> io::Result<u64> { fields[index].parse().map_err(|_| invalid("stat field")) };
    let state = fields[0].chars().next().filter(|_| fields[0].len() == 1).ok_or_else(|| invalid("stat state"))?;
    Ok(Stat {
        state,
        ppid: fields[1].parse().map_err(|_| invalid("stat ppid"))?,
        utime_ticks: number(11)?,
        start_ticks: number(19)?,
    })
}

/// The boot ID (/proc/sys/kernel/random/boot_id), which every report names.
pub fn boot_id() -> io::Result<String> {
    Ok(read::text("/proc/sys/kernel/random/boot_id")?.trim().to_string())
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}
