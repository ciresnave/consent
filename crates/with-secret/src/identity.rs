// SPDX-License-Identifier: MIT OR Apache-2.0
//! Who is asking. ⚠️ Taken from the OS process table and lane-state files,
//! never from an argument - a lane cannot name itself into another lane's
//! approval. (A deliberate same-user process could forge a lane-state file;
//! design §3.)

use std::path::Path;

use lane_restart::facts::ProcEntry;
use lane_restart::state::LaneState;
/// Moved to `user-request`, unchanged: with-secret's approval cache signs
/// its serialised form.
pub use user_request::Requester;

fn is_claude(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "claude.exe" || n == "claude"
}

pub fn resolve(
    table: &[ProcEntry],
    self_pid: u32,
    states: &[LaneState],
) -> Result<Requester, String> {
    let find = |pid: u32| table.iter().find(|e| e.pid == pid);
    let me = find(self_pid).ok_or_else(|| format!("pid {self_pid} is not in the process table"))?;
    let first_parent = me
        .parent
        .and_then(find)
        .filter(|p| p.start_time_secs <= me.start_time_secs);

    let mut child = me;
    for _ in 0..64 {
        let Some(parent) = child.parent.and_then(find) else {
            break;
        };
        if parent.start_time_secs > child.start_time_secs {
            break;
        } // reused pid
        if is_claude(&parent.name) {
            return Ok(match states.iter().find(|s| s.pid == parent.pid) {
                Some(s) => Requester {
                    role: s.role.clone(),
                    session_id: s.session_id.clone(),
                    claude_pid: parent.pid,
                    claude_start_secs: parent.start_time_secs,
                    managed: true,
                },
                None => Requester {
                    role: "unmanaged-claude".into(),
                    session_id: String::new(),
                    claude_pid: parent.pid,
                    claude_start_secs: parent.start_time_secs,
                    managed: false,
                },
            });
        }
        child = parent;
    }
    let anchor = first_parent.unwrap_or(me);
    Ok(Requester {
        role: "outside-claude".into(),
        session_id: String::new(),
        claude_pid: anchor.pid,
        claude_start_secs: anchor.start_time_secs,
        managed: false,
    })
}

pub fn load_states(dir: &Path) -> Vec<LaneState> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            (path.extension()? == "json").then(|| path.file_stem()?.to_str().map(String::from))?
        })
        .filter_map(|role| lane_restart::state::load(dir, &role).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lane_restart::facts::ProcEntry;
    use lane_restart::state::LaneState;

    fn p(pid: u32, parent: Option<u32>, name: &str, start: u64) -> ProcEntry {
        ProcEntry {
            pid,
            parent,
            name: name.into(),
            start_time_secs: start,
            exe: None,
        }
    }

    fn state(role: &str, pid: u32, session: &str) -> LaneState {
        serde_json::from_value(serde_json::json!({
            "role": role, "session_id": session, "pid": pid, "cwd": "C:\\Projects\\X",
            "remote_control": false, "busy": false, "subagents_running": 0,
            "updated_at": "2026-10-01T00:00:00Z", "updated_by_event": "test"
        }))
        .unwrap()
    }

    // claude(10) -> bash(20) -> with-secret(30)
    fn table() -> Vec<ProcEntry> {
        vec![
            p(1, None, "explorer.exe", 1),
            p(10, Some(1), "claude.exe", 100),
            p(20, Some(10), "bash.exe", 200),
            p(30, Some(20), "with-secret.exe", 300),
        ]
    }

    #[test]
    fn a_lane_is_identified_by_its_claude_ancestor_and_state() {
        let r = resolve(&table(), 30, &[state("humboldt", 10, "s-1")]).unwrap();
        assert_eq!(
            r,
            Requester {
                role: "humboldt".into(),
                session_id: "s-1".into(),
                claude_pid: 10,
                claude_start_secs: 100,
                managed: true
            }
        );
    }

    #[test]
    fn a_claude_with_no_state_is_unmanaged() {
        let r = resolve(&table(), 30, &[state("other", 999, "s-9")]).unwrap();
        assert_eq!(r.role, "unmanaged-claude");
        assert!(!r.managed);
        assert_eq!(r.claude_pid, 10);
    }

    #[test]
    fn no_claude_ancestor_is_outside_claude_keyed_on_the_parent() {
        let t = vec![
            p(1, None, "explorer.exe", 1),
            p(20, Some(1), "pwsh.exe", 200),
            p(30, Some(20), "with-secret.exe", 300),
        ];
        let r = resolve(&t, 30, &[]).unwrap();
        assert_eq!(r.role, "outside-claude");
        assert_eq!((r.claude_pid, r.claude_start_secs), (20, 200));
    }

    #[test]
    fn a_reused_parent_pid_stops_the_walk() {
        // pid 10 was reused by a claude that started AFTER its "child".
        let t = vec![
            p(10, None, "claude.exe", 500),
            p(20, Some(10), "bash.exe", 200),
            p(30, Some(20), "with-secret.exe", 300),
        ];
        let r = resolve(&t, 30, &[state("humboldt", 10, "s-1")]).unwrap();
        assert_eq!(r.role, "outside-claude", "trusted a reused pid");
    }

    #[test]
    fn self_missing_from_the_table_fails_closed() {
        assert!(resolve(&table(), 77, &[]).is_err());
    }

    #[test]
    fn a_restarted_lane_is_a_different_requester() {
        let before = resolve(&table(), 30, &[state("humboldt", 10, "s-1")]).unwrap();
        let mut t = table();
        t[1] = p(11, Some(1), "claude.exe", 900);
        t[2] = p(20, Some(11), "bash.exe", 950);
        t[3] = p(30, Some(20), "with-secret.exe", 960);
        let after = resolve(&t, 30, &[state("humboldt", 11, "s-2")]).unwrap();
        assert_eq!(before.role, after.role);
        assert_ne!(before, after);
    }
}
