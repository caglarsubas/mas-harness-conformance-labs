//! TG-05 clocks (W04-4a, CONF-ENF-004): the native part of five of the plan's six TG-05 cases, run on the enrolled
//! AMD64 and ARM64 hosts in W06, never before (D-MAP). Each case injects one fault and records a timeline (common::
//! timeline); the verdicts come from that timeline and W06's answer log (tests/enforcement/tg05_clocks/_verdicts.py).
//! TG-05's S8-FREEZE is record-level and has no probe here; its kernel fact is TG-04's S8-FREEZE.
//!
//! Usage: `tg05_clocks <case> <binding>`. `faultResult` in the `end` record is PASS only when the fault took effect as the
//! case needs; it is never a case result.
#![forbid(unsafe_code)]

mod expected;

use common::binding::{describe, Binding};
use common::cgroup;
use common::proc;
use common::role;
use common::sys::{self, PidFd};
use common::time::{self, Clocks, NS_PER_S};
use common::timeline::{self, boolean, clocks, number, record, string, Json};
use std::fs;
use std::panic;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

struct Case {
    tag: &'static str,
    name: &'static str,
    keys: &'static [&'static str],
    run: fn(&Binding) -> Result<(), String>,
}

// Every binding names the W06 route the probe runs under and the loaded policy's digest (owner decision Q-T14), which
// the start record reports with the rest of the binding.
const CASES: [Case; 5] = [
    Case { tag: "MATRIX:expiry with stalled Python", name: "expiry_with_stalled_python",
           keys: &["route", "policyDigest", "expiresAt", "execution"], run: expiry_with_stalled_python },
    Case { tag: "MATRIX:suspend", name: "suspend", keys: &["route", "policyDigest", "expiresAt", "execution"], run: suspend },
    Case { tag: "MATRIX:wall-clock rollback", name: "wall_clock_rollback",
           keys: &["route", "policyDigest", "expiresAt", "execution"], run: wall_clock_rollback },
    Case { tag: "MATRIX:peer death/restart", name: "peer_death_restart",
           keys: &["route", "policyDigest", "expiresAt", "peer", "execution"], run: peer_death_restart },
    Case { tag: "MATRIX:original deadlines", name: "original_deadlines",
           keys: &["route", "policyDigest", "expiresAt", "execution"], run: original_deadlines },
];

// Test parameters of this probe (not contract values): how long a fault is held after the deadline so that W06's driver
// can send the requests the verdicts judge, how far the wall clock is set back beyond the deadline, how long to wait
// for a killed role's restart, and how often to poll.
const HOLD_AFTER_DEADLINE_NS: i128 = 60 * NS_PER_S;
const ROLLBACK_BEYOND_DEADLINE_NS: i128 = 3_600 * NS_PER_S;
const WAKE_AFTER_DEADLINE_S: i128 = 60;
const RESTART_WAIT_NS: i128 = 300 * NS_PER_S;
const EXIT_WAIT_MS: i32 = 2_000;
const STOP_ROUNDS: usize = 5;
const POLL: Duration = Duration::from_millis(100);

/// Set by a restore guard that could not restore: the run is then NOT_RUN and W06's harness restore must run (review D3-6).
static RESTORE_FAILED: AtomicBool = AtomicBool::new(false);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let case = match CASES.iter().find(|case| args.len() == 3 && case.name == args[1]) {
        Some(case) => case,
        None => {
            eprintln!("usage: tg05_clocks <{}> <binding>", CASES.iter().map(|case| case.name).collect::<Vec<_>>().join("|"));
            std::process::exit(2);
        }
    };
    let binding = Binding::load(&args[2], case.keys);
    let pairs: Vec<(&str, Json)> = match &binding {
        Ok(binding) => binding.pairs().into_iter().map(|(key, value)| (leak(key), string(&value))).collect(),
        Err(_) => vec![],
    };
    let start = Clocks::now().ok();
    record("start", &[
        ("case", string(case.tag)),
        ("arch", string(if cfg!(target_arch = "x86_64") { "x86_64" } else { "aarch64" })),
        ("bootId", string(&proc::boot_id().unwrap_or_default())),
        ("probeTree", string(common::tree::PROBE_TREE)),
        ("binding", timeline::object(&pairs)),
        ("clocks", start.as_ref().map(clocks).unwrap_or_else(timeline::null)),
    ]);
    let outcome = match binding {
        Err(reason) => Err(reason),
        Ok(binding) => panic::catch_unwind(|| (case.run)(&binding)).unwrap_or_else(|_| Err("the probe panicked".to_string())),
    };
    match outcome {
        Ok(()) if RESTORE_FAILED.load(Ordering::SeqCst) => record("end", &[("faultResult", string("NOT_RUN_ENV_UNAVAILABLE")),
                                                                         ("reason", string("a restore failed"))]),
        Ok(()) if !timeline::write_failed() => record("end", &[("faultResult", string("PASS")), ("reason", timeline::null())]),
        Ok(()) => record("end", &[("faultResult", string("NOT_RUN_ENV_UNAVAILABLE")), ("reason", string("a record was not written"))]),
        Err(reason) => record("end", &[("faultResult", string("NOT_RUN_ENV_UNAVAILABLE")), ("reason", string(&reason))]),
    }
    if timeline::write_failed() {
        std::process::exit(3);
    }
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn role_path(role: &str) -> &'static str {
    expected::ROLES.iter().find(|row| row.0 == role).map(|row| row.1).unwrap_or("")
}

fn now() -> Result<Clocks, String> {
    Clocks::now().map_err(|error| format!("clock: {}", describe(&error)))
}

/// Records the signed expiry mapped onto BOOTTIME before any fault; refuses one not ahead of the wall clock.
fn deadline(binding: &Binding) -> Result<i128, String> {
    let text = binding.get("expiresAt");
    let seconds = time::parse_utc(text).ok_or_else(|| format!("expiresAt {} is not a canonical UTC time", text))?;
    let at = now()?;
    let remaining = seconds as i128 * NS_PER_S - at.realtime;
    if remaining <= 0 {
        return Err("expiresAt is not ahead of the wall clock".to_string());
    }
    let boottime = at.boottime + remaining;
    record("deadline", &[("expiresAt", string(text)), ("boottime", number(boottime)), ("clocks", clocks(&at))]);
    Ok(boottime)
}

/// The worker leaf holds the tested execution's processes now (the binding names the execution); records their identities.
fn leaf_members() -> Result<Vec<(i32, u64, PidFd)>, String> {
    let leaf = Path::new(role_path("WORKER"));
    let events = cgroup::events(leaf).map_err(|error| format!("worker leaf cgroup.events: {}", describe(&error)))?;
    if !events.populated {
        return Err("the worker leaf is empty: no execution is running".to_string());
    }
    let mut members = Vec::new();
    for pid in cgroup::procs(leaf).map_err(|error| format!("worker leaf cgroup.procs: {}", describe(&error)))? {
        let pidfd = PidFd::open(pid).map_err(|error| format!("worker {} pidfd_open: {}", pid, describe(&error)))?;
        let stat = proc::stat(pid).map_err(|error| format!("worker {} stat: {}", pid, describe(&error)))?;
        members.push((pid, stat.start_ticks, pidfd));
    }
    record("observation", &[("name", string("workerLeaf")), ("value", Json(format!("[{}]", members.iter()
        .map(|(pid, ticks, _)| timeline::object(&[("pid", number(pid)), ("startTicks", number(ticks))]).0)
        .collect::<Vec<_>>().join(",")))), ("clocks", clocks(&now()?))]);
    Ok(members)
}

/// Sleeps until BOOTTIME passes `until`.
fn wait_until(until: i128) -> Result<(), String> {
    while now()?.boottime < until {
        sleep(POLL);
    }
    Ok(())
}

/// Whether the process the pidfd pins is alive and stopped (the pidfd rules out a reused PID).
fn stopped(pid: i32, pidfd: &PidFd) -> bool {
    !pidfd.exited_within(0).unwrap_or(true) && matches!(proc::stat(pid), Ok(stat) if stat.state == 'T')
}

/// Sends SIGCONT to the stopped processes when dropped, so a failure or panic never leaves them stopped.
struct Continue(Vec<(i32, PidFd)>);

impl Drop for Continue {
    fn drop(&mut self) {
        // A process that has exited (the broker may kill the worker leaf on expiry) needs no SIGCONT.
        let sent = self.0.iter().filter(|(_, pidfd)| !pidfd.exited_within(0).unwrap_or(false))
            .all(|(_, pidfd)| pidfd.signal(sys::SIGCONT).is_ok());
        if !sent {
            RESTORE_FAILED.store(true, Ordering::SeqCst);
        }
        let at = Clocks::now().map(|at| clocks(&at)).unwrap_or_else(|_| timeline::null());
        record("fault", &[("fault", string("SIGCONT")), ("applied", boolean(sent)), ("clocks", at)]);
    }
}

/// MATRIX:expiry with stalled Python: every process of the CPython roles (the roles with an interpreter in native v3:
/// SERVER, and the worker leaf's processes) is stopped before the deadline, and SERVER is held stopped until the deadline
/// plus the hold, then every stopped process still alive is continued. The worker processes may end meanwhile: on expiry
/// the broker kills the leaf (W02D 5.4 W6); their exits are recorded, not required.
fn expiry_with_stalled_python(binding: &Binding) -> Result<(), String> {
    let deadline = deadline(binding)?;
    let workers = leaf_members()?;
    let server = role::single("SERVER", role_path("SERVER"))?;
    let server_pid = server.pid;
    let mut held = Continue(vec![(server.pid, server.pidfd)]);
    held.0.extend(workers.into_iter().map(|(pid, _, pidfd)| (pid, pidfd)));
    let mut applied = true;
    // Stop every process of the CPython roles, then list them again until no unstopped process remains (a worker may
    // fork between the listing and the signal: review R1-6).
    for _ in 0..STOP_ROUNDS {
        for (pid, pidfd) in &held.0 {
            if let Err(error) = pidfd.signal(sys::SIGSTOP) {
                applied = false;
                record("observation", &[("name", string("signalRefused")), ("value", string(&format!("{}: {}", pid, describe(&error)))),
                                        ("clocks", clocks(&now()?))]);
            }
        }
        sleep(POLL);
        let mut fresh = Vec::new();
        for (name, path, interpreter) in expected::ROLES.iter() {
            if interpreter.is_none() {
                continue;
            }
            for pid in cgroup::procs(Path::new(path)).map_err(|error| format!("{} cgroup.procs: {}", name, describe(&error)))? {
                // A PID counts as held only while its held process lives (review R4-5: a reused PID is a new process).
                if !held.0.iter().any(|(known, pidfd)| *known == pid && !pidfd.exited_within(0).unwrap_or(true)) {
                    fresh.push((pid, *name, *path));
                }
            }
        }
        if fresh.is_empty() {
            break;
        }
        for (pid, name, path) in fresh {
            // Pin the process, then check the pinned process is still in the role's cgroup: a PID reused after the
            // listing by a process outside it is refused, never stopped (reviews R2-4, R3-3).
            let pidfd = PidFd::open(pid).map_err(|error| format!("{} pidfd_open: {}", pid, describe(&error)))?;
            let members = cgroup::procs(Path::new(path)).map_err(|error| format!("{} cgroup.procs: {}", name, describe(&error)))?;
            if pidfd.exited_within(0).unwrap_or(true) || !members.contains(&pid) {
                return Err(format!("process {} left the {} cgroup while it was pinned", pid, name));
            }
            held.0.push((pid, pidfd));
        }
    }
    let mut listed: Vec<i32> = Vec::new();
    for (name, path, interpreter) in expected::ROLES.iter() {
        if interpreter.is_some() {
            listed.extend(cgroup::procs(Path::new(path)).map_err(|error| format!("{} cgroup.procs: {}", name, describe(&error)))?);
        }
    }
    let all = applied && listed.iter().all(|pid| held.0.iter().any(|(known, pidfd)| known == pid && !pidfd.exited_within(0).unwrap_or(true)))
        && held.0.iter().all(|(pid, pidfd)| pidfd.exited_within(0).unwrap_or(false) || stopped(*pid, pidfd));
    let pids = Json(format!("[{}]", held.0.iter().map(|(pid, _)| pid.to_string()).collect::<Vec<_>>().join(",")));
    record("fault", &[("fault", string("SIGSTOP")), ("pids", pids), ("applied", boolean(all)), ("clocks", clocks(&now()?))]);
    if !all {
        return Err("the CPython roles could not all be stopped".to_string());
    }
    if now()?.boottime >= deadline {
        return Err("the CPython roles were stopped only after the deadline".to_string());
    }
    wait_until(deadline + HOLD_AFTER_DEADLINE_NS)?;
    let exited: Vec<String> = held.0.iter().filter(|(_, pidfd)| pidfd.exited_within(0).unwrap_or(false))
        .map(|(pid, _)| pid.to_string()).collect();
    record("observation", &[("name", string("exitedDuringStall")), ("value", Json(format!("[{}]", exited.join(",")))),
                            ("clocks", clocks(&now()?))]);
    if !stopped(server_pid, &held.0[0].1) {
        return Err("SERVER left the stopped state before the hold ended".to_string());
    }
    drop(held);
    Ok(())
}

/// MATRIX:suspend: the host suspends from now until an RTC alarm after the deadline.
fn suspend(binding: &Binding) -> Result<(), String> {
    let deadline = deadline(binding)?;
    leaf_members()?;
    let wake = time::parse_utc(binding.get("expiresAt")).unwrap_or(0) as i128 + WAKE_AFTER_DEADLINE_S;
    let before = now()?;
    let written = fs::write("/sys/class/rtc/rtc0/wakealarm", "0")
        .and_then(|_| fs::write("/sys/class/rtc/rtc0/wakealarm", wake.to_string()))
        .and_then(|_| fs::write("/sys/power/state", "mem"));
    let after = now()?;
    let slept = (after.boottime - after.monotonic) - (before.boottime - before.monotonic);
    let applied = written.is_ok() && slept >= NS_PER_S && before.boottime < deadline && deadline < after.boottime;
    record("fault", &[("fault", string("SUSPEND")), ("applied", boolean(applied)), ("suspendedNs", number(slept)),
                      ("clocksBefore", clocks(&before)), ("clocks", clocks(&after))]);
    match written {
        Err(error) => Err(format!("suspend: {}", describe(&error))),
        Ok(()) if !applied => Err("the suspend did not cover the deadline".to_string()),
        Ok(()) => Ok(()),
    }
}

/// Restores the wall clock from the MONOTONIC time elapsed since `start` when dropped, on every path.
struct Restore(Clocks);

impl Drop for Restore {
    fn drop(&mut self) {
        let done = Clocks::now().ok().map(|at| sys::set_realtime_ns(self.0.realtime + (at.monotonic - self.0.monotonic)).is_ok());
        if done != Some(true) {
            RESTORE_FAILED.store(true, Ordering::SeqCst);
        }
        let at = Clocks::now().map(|at| clocks(&at)).unwrap_or_else(|_| timeline::null());
        record("restore", &[("what", string("CLOCK_SET")), ("done", boolean(done == Some(true))), ("clocks", at)]);
    }
}

/// MATRIX:wall-clock rollback: before the deadline the wall clock is set back beyond it, held there until the deadline
/// plus the hold (on BOOTTIME), then restored.
fn wall_clock_rollback(binding: &Binding) -> Result<(), String> {
    let deadline = deadline(binding)?;
    leaf_members()?;
    let start = now()?;
    let back = (deadline - start.boottime) + ROLLBACK_BEYOND_DEADLINE_NS;
    let set = sys::set_realtime_ns(start.realtime - back);
    let restore = Restore(start);
    let at = now()?;
    let moved = start.realtime + (at.monotonic - start.monotonic) - at.realtime;
    let applied = set.is_ok() && moved >= back - NS_PER_S;
    record("fault", &[("fault", string("CLOCK_SET")), ("applied", boolean(applied)), ("rolledBackNs", number(moved)),
                      ("clocks", clocks(&at))]);
    if let Err(error) = set {
        return Err(format!("clock_settime: {}", describe(&error)));
    }
    if !applied {
        return Err("the wall clock did not move back".to_string());
    }
    wait_until(deadline + HOLD_AFTER_DEADLINE_NS)?;
    let at = now()?;
    record("observation", &[("name", string("rolledBackAtRestore")),
                            ("value", number(start.realtime + (at.monotonic - start.monotonic) - at.realtime)), ("clocks", clocks(&at))]);
    drop(restore);
    Ok(())
}

/// Waits for a process of `role`'s cgroup with an identity other than (pid, start ticks); records it.
fn restarted(role_name: &'static str, pid: i32, start_ticks: u64) -> Result<bool, String> {
    let begin = now()?;
    while now()?.boottime - begin.boottime <= RESTART_WAIT_NS {
        if let Ok(new) = role::single(role_name, role_path(role_name)) {
            if (new.pid, new.stat.start_ticks) != (pid, start_ticks) {
                record("observation", &[("name", string("restarted")), ("value", timeline::object(&[
                    ("role", string(role_name)), ("pid", number(new.pid)), ("startTicks", number(new.stat.start_ticks))])),
                    ("clocks", clocks(&now()?))]);
                return Ok(true);
            }
        }
        sleep(POLL);
    }
    Ok(false)
}

/// Kills `role_name`'s process through its pidfd and waits for the exit.
fn kill(role_name: &'static str) -> Result<(i32, u64), String> {
    let process = role::single(role_name, role_path(role_name))?;
    let sent = process.pidfd.signal(sys::SIGKILL);
    let exited = sent.is_ok() && process.pidfd.exited_within(EXIT_WAIT_MS).unwrap_or(false);
    record("fault", &[("fault", string("SIGKILL")), ("role", string(role_name)), ("pid", number(process.pid)),
                      ("startTicks", number(process.stat.start_ticks)), ("applied", boolean(exited)), ("clocks", clocks(&now()?))]);
    match sent {
        Err(error) => Err(format!("pidfd_send_signal: {}", describe(&error))),
        Ok(()) if !exited => Err(format!("{} did not exit after SIGKILL", role_name)),
        Ok(()) => Ok((process.pid, process.stat.start_ticks)),
    }
}

/// MATRIX:peer death/restart: a peer of the reader (OBSERVER or BROKER) is killed while the reader serves an execution;
/// its restart, if any, is recorded.
fn peer_death_restart(binding: &Binding) -> Result<(), String> {
    let peer: &'static str = match binding.get("peer") {
        "OBSERVER" => "OBSERVER",
        "BROKER" => "BROKER",
        other => return Err(format!("peer {} is neither OBSERVER nor BROKER", other)),
    };
    // The reader checks end at the tested execution's deadline (reviews D3-3, D4-1).
    let deadline = deadline(binding)?;
    leaf_members()?;
    let (pid, ticks) = kill(peer)?;
    if now()?.boottime >= deadline {
        return Err("the peer was killed only after the deadline".to_string());
    }
    restarted(peer, pid, ticks)?;
    Ok(())
}

/// MATRIX:original deadlines: the reader (SERVER) is killed before the deadline and must restart.
fn original_deadlines(binding: &Binding) -> Result<(), String> {
    let deadline = deadline(binding)?;
    leaf_members()?;
    let (pid, ticks) = kill("SERVER")?;
    if now()?.boottime >= deadline {
        return Err("the reader was killed only after the deadline".to_string());
    }
    if !restarted("SERVER", pid, ticks)? {
        return Err("the reader did not restart".to_string());
    }
    Ok(())
}
