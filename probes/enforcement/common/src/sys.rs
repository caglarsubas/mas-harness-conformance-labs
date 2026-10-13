//! The only module with `unsafe`: thin wrappers over musl's libc. Linux-specific calls go through `syscall()` with
//! numbers from `nr.rs` (generated from the seccomp v2 syscall table); POSIX calls use musl's own functions.
//! Constants below are Linux UAPI values at v6.12, the kernel the seccomp v2 table cites; they are interface facts,
//! not expected results.
use std::io;

/// include/uapi/linux/time.h
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_BOOTTIME: i32 = 7;
/// include/uapi/asm-generic/signal.h (x86 uses the same numbers for these three)
pub const SIGKILL: i32 = 9;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
/// include/uapi/asm-generic/poll.h
const POLLIN: i16 = 1;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

extern "C" {
    fn syscall(number: i64, ...) -> i64;
    fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
    fn clock_settime(clock: i32, value: *const Timespec) -> i32;
    fn poll(fds: *mut PollFd, count: u64, timeout_ms: i32) -> i32;
    fn close(fd: i32) -> i32;
}

/// Nanoseconds on `clock`.
pub fn clock_ns(clock: i32) -> io::Result<i128> {
    let mut value = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `value` is a valid, writable timespec for the duration of the call.
    if unsafe { clock_gettime(clock, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value.tv_sec as i128 * 1_000_000_000 + value.tv_nsec as i128)
}

/// Sets CLOCK_REALTIME to `ns` nanoseconds after the epoch (needs CAP_SYS_TIME).
pub fn set_realtime_ns(ns: i128) -> io::Result<()> {
    if ns < 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let value = Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
    // SAFETY: `value` is a valid timespec for the duration of the call.
    if unsafe { clock_settime(CLOCK_REALTIME, &value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// An owned pidfd; closed on drop.
pub struct PidFd(i32);

impl PidFd {
    /// pidfd_open(pid, 0).
    pub fn open(pid: i32) -> io::Result<PidFd> {
        // SAFETY: pidfd_open takes two integer arguments and returns a new descriptor or -1.
        let fd = unsafe { syscall(crate::nr::PIDFD_OPEN, pid as i64, 0i64) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PidFd(fd as i32))
    }

    /// pidfd_send_signal(fd, signal, NULL, 0).
    pub fn signal(&self, signal: i32) -> io::Result<()> {
        // SAFETY: a null siginfo pointer is allowed; the other arguments are integers.
        let result = unsafe { syscall(crate::nr::PIDFD_SEND_SIGNAL, self.0 as i64, signal as i64, 0i64, 0i64) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Whether the process has exited, waiting up to `timeout_ms` (a pidfd polls readable once it exits).
    pub fn exited_within(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut entry = PollFd { fd: self.0, events: POLLIN, revents: 0 };
        // SAFETY: `entry` is one valid pollfd for the duration of the call.
        let ready = unsafe { poll(&mut entry, 1, timeout_ms) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ready == 1 && entry.revents & POLLIN != 0)
    }
}

impl Drop for PidFd {
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by this value and closed once.
        unsafe {
            close(self.0);
        }
    }
}
