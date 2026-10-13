//! Shared parts of the W04 native probes (R12 enforcement area, CONF-ENF-004).
//!
//! Standard library only. `sys` is the only module that may use `unsafe`; every other module and both probe crates
//! forbid it. The probes inject one native fault each and record a timeline; they decide no case (the verdicts are
//! tests/enforcement's). Contract values come from `expected.rs` in each probe crate, generated from the snapshots; the
//! host binding supplies run facts only.
#![deny(unsafe_code)]

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!("the probes target x86_64 and aarch64 Linux only");

pub mod binding;
pub mod cgroup;
pub mod nr;
pub mod proc;
pub mod read;
pub mod role;
#[allow(unsafe_code)]
pub mod sys;
pub mod time;
pub mod timeline;
pub mod tree;
