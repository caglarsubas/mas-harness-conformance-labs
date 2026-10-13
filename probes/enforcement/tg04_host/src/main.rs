//! TG-04 host probes: the source comes with CONF-ENF-005 (W04-4b, owner decision 2026-10-13). Until then this binary
//! records that no TG-04 fault exists and ends NOT_RUN_ENV_UNAVAILABLE, whatever case it is asked for.
#![forbid(unsafe_code)]

use common::timeline::{record, string};

fn main() {
    let case = std::env::args().nth(1).unwrap_or_default();
    record("start", &[("case", string(&case)), ("probeTree", string(common::tree::PROBE_TREE))]);
    record("end", &[("faultResult", string("NOT_RUN_ENV_UNAVAILABLE")),
                    ("reason", string("no TG-04 probe source in CONF-ENF-004; it comes with CONF-ENF-005"))]);
}
