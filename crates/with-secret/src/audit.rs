// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every access attempt, as JSON lines. ⚠️ NEVER the value. CireSnave on the
//! auditor's kill-log, same spirit: the record is what makes it reviewable.

use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub at: DateTime<Utc>,
    pub event: String, // granted | used | denied | timed-out | unavailable | refused
    pub secret: String,
    pub role: String,
    pub session_id: String,
    pub claude_pid: u32,
    pub command: String,
    pub reason: String,
}

pub fn append(path: &Path, e: &Event) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("open {}: {err}", path.display()))?;
    writeln!(
        f,
        "{}",
        serde_json::to_string(e).map_err(|err| err.to_string())?
    )
    .map_err(|err| err.to_string())
}
