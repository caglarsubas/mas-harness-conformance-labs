//! Canonical UTC times (`%Y-%m-%dT%H:%M:%SZ`, the native qualification v3 TIME format) and clock reads.
use crate::sys;
use std::io;

/// Seconds since the epoch of a canonical UTC time; `None` unless `text` is exactly canonical.
pub fn parse_utc(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<i64> {
        let part = &text[from..to];
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    if format_utc(seconds) != text {
        return None;
    }
    Some(seconds)
}

/// The canonical UTC text of `seconds` since the epoch.
pub fn format_utc(seconds: i64) -> String {
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, rest / 3_600, rest % 3_600 / 60, rest % 60)
}

fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's civil-calendar algorithms (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, month, day)
}

/// One reading of the three clocks the TG-05 cases compare, in nanoseconds.
#[derive(Clone, Copy, Debug)]
pub struct Clocks {
    pub realtime: i128,
    pub monotonic: i128,
    pub boottime: i128,
}

impl Clocks {
    pub fn now() -> io::Result<Clocks> {
        Ok(Clocks {
            realtime: sys::clock_ns(sys::CLOCK_REALTIME)?,
            monotonic: sys::clock_ns(sys::CLOCK_MONOTONIC)?,
            boottime: sys::clock_ns(sys::CLOCK_BOOTTIME)?,
        })
    }
}

pub const NS_PER_S: i128 = 1_000_000_000;
pub const NS_PER_MS: i128 = 1_000_000;
