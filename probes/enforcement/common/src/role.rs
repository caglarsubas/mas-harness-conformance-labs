//! A resident role's single process, found through its contract cgroup path and pinned by a pidfd.
use crate::binding::describe;
use crate::cgroup;
use crate::proc::{self, Stat};
use crate::sys::PidFd;
use std::path::Path;

pub struct RoleProcess {
    pub role: &'static str,
    pub pid: i32,
    pub stat: Stat,
    pub pidfd: PidFd,
}

/// The one process of `role`'s cgroup. The pidfd is opened first and the start ticks are read again afterwards, so the
/// pidfd refers to the process whose identity is reported (a reused PID would show different start ticks).
pub fn single(role: &'static str, cgroup_path: &str) -> Result<RoleProcess, String> {
    let pids = cgroup::procs(Path::new(cgroup_path)).map_err(|error| format!("{} cgroup.procs: {}", role, describe(&error)))?;
    if pids.len() != 1 {
        return Err(format!("{} cgroup holds {} processes, not one", role, pids.len()));
    }
    let pid = pids[0];
    let before = proc::stat(pid).map_err(|error| format!("{} stat: {}", role, describe(&error)))?;
    let pidfd = PidFd::open(pid).map_err(|error| format!("{} pidfd_open: {}", role, describe(&error)))?;
    let after = proc::stat(pid).map_err(|error| format!("{} stat after pidfd_open: {}", role, describe(&error)))?;
    if before.start_ticks != after.start_ticks {
        return Err(format!("{} process changed while its pidfd was opened", role));
    }
    Ok(RoleProcess { role, pid, stat: after, pidfd })
}
