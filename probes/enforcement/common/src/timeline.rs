//! The probe's output: one JSON object per line (schema `r12.enforcement-probe-timeline/v1`), `start` first and `end`
//! last. The probe records what it did and saw; it never decides a case. The verdicts are made from this timeline and
//! W06's answer log by tests/enforcement/tg05_clocks/_verdicts.py.
use crate::time::Clocks;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

static WRITE_FAILED: AtomicBool = AtomicBool::new(false);

pub const SCHEMA: &str = "r12.enforcement-probe-timeline/v1";

/// A JSON value already encoded.
pub struct Json(pub String);

pub fn string(value: &str) -> Json {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Json(out)
}

pub fn number(value: impl std::fmt::Display) -> Json {
    Json(value.to_string())
}

pub fn boolean(value: bool) -> Json {
    Json(if value { "true" } else { "false" }.to_string())
}

pub fn null() -> Json {
    Json("null".to_string())
}

pub fn clocks(value: &Clocks) -> Json {
    Json(format!("{{\"realtime\":{},\"monotonic\":{},\"boottime\":{}}}", value.realtime, value.monotonic, value.boottime))
}

pub fn object(fields: &[(&str, Json)]) -> Json {
    let body: Vec<String> = fields.iter().map(|(name, value)| format!("{}:{}", string(name).0, value.0)).collect();
    Json(format!("{{{}}}", body.join(",")))
}

/// Writes one record: `kind` plus `fields`, with the schema version first. A failed write is remembered (`write_failed`)
/// and the probe carries on, so its restores still run; a timeline missing a record is refused by the verdicts.
pub fn record(kind: &str, fields: &[(&str, Json)]) {
    let mut all = vec![("schemaVersion", string(SCHEMA)), ("kind", string(kind))];
    all.extend(fields.iter().map(|(name, value)| (*name, Json(value.0.clone()))));
    let line = object(&all).0;
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{}", line).and_then(|_| out.flush()).is_err() {
        WRITE_FAILED.store(true, Ordering::SeqCst);
    }
}

/// Whether any record could not be written.
pub fn write_failed() -> bool {
    WRITE_FAILED.load(Ordering::SeqCst)
}
