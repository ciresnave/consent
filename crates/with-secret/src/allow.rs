// SPDX-License-Identifier: MIT OR Apache-2.0
//! `vault allow`: change who may request an entry, without re-entering the
//! value (WITH-SECRET-REQUESTER-ALLOWLIST-DESIGN.md §4). This module is the
//! pure part: parse the arguments, plan the new lists, word the prompt and
//! the binding. `main.rs` does the I/O.
//!
//! ⚠️ A filter before the prompt, not a boundary: a same-user process can still
//! read the vault directly.

use crate::vault::{validate_name, Vault};

/// How one entry's list changes.
#[derive(Debug, Clone, PartialEq)]
pub enum Edit {
    /// `--lanes a,b` / `--lanes none` / a `--file` entry: the new list.
    Replace(Vec<String>),
    Add(Vec<String>),
    Remove(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub name: String,
    pub edit: Edit,
}

/// One entry's list before and after.
#[derive(Debug, Clone, PartialEq)]
pub struct Planned {
    pub name: String,
    pub old: Vec<String>,
    pub new: Vec<String>,
}

/// At most this many entries are spelled out in the Hello text; the rest are
/// counted. The binding always covers all of them.
const PROMPT_ENTRIES: usize = 8;
/// A list longer than this is cut in the Hello text, with a count.
const PROMPT_LIST_CHARS: usize = 120;
/// The unclipped "newly allowed" line may not be longer than this.
const MAX_GAINED_CHARS: usize = 300;

fn check_lane(l: &str) -> Result<(), String> {
    if l.trim().is_empty() || l == "none" || l.starts_with("--") || l.contains(',') {
        return Err(format!("'{l}' is not a lane name"));
    }
    if l.trim() != l || l.chars().any(char::is_control) {
        return Err(format!(
            "{l:?} is not a lane name (whitespace around it, or a control character)"
        ));
    }
    Ok(())
}

fn lane_list(arg: &str) -> Result<Vec<String>, String> {
    crate::vault::parse_lanes(arg)
}

fn nonempty(v: Vec<String>, flag: &str) -> Result<Vec<String>, String> {
    if v.is_empty() {
        Err(format!(
            "{flag} needs at least one lane (`none` is only for --lanes)"
        ))
    } else {
        Ok(v)
    }
}

/// `args` follow `vault allow`. Exactly one of: `NAME --lanes L`,
/// `NAME --add L`, `NAME --remove L`, `--file F`. `read_file` fetches F.
pub fn parse_args(
    args: &[String],
    read_file: impl FnOnce(&str) -> Result<String, String>,
) -> Result<Vec<Change>, String> {
    const USAGE: &str = "usage: vault allow NAME (--lanes a,b|none | --add a,b | --remove a,b) \
                         | vault allow --file lanes.json";
    let flag_value = |flag: &str| -> Result<Option<&String>, String> {
        match args.iter().position(|a| a == flag) {
            None => Ok(None),
            Some(i) => args
                .get(i + 1)
                .map(Some)
                .ok_or_else(|| format!("{flag} needs a value")),
        }
    };
    let file = flag_value("--file")?;
    let lanes = flag_value("--lanes")?;
    let add = flag_value("--add")?;
    let remove = flag_value("--remove")?;
    let modes = [file, lanes, add, remove]
        .iter()
        .filter(|m| m.is_some())
        .count();
    if modes != 1 {
        return Err(USAGE.into());
    }
    if let Some(f) = file {
        // nothing but the flag and its value
        if args.len() != 2 {
            return Err(USAGE.into());
        }
        let text = read_file(f)?;
        let map = parse_file(&text).map_err(|e| format!("--file {f}: {e}"))?;
        if map.is_empty() {
            return Err(format!("--file {f}: no entries"));
        }
        let mut out = Vec::new();
        for (name, lanes) in map {
            validate_name(&name)?;
            for l in &lanes {
                check_lane(l).map_err(|e| format!("--file {f}: {name}: {e}"))?;
            }
            let mut dedup: Vec<String> = Vec::new();
            for l in lanes {
                if !dedup.contains(&l) {
                    dedup.push(l);
                }
            }
            out.push(Change {
                name,
                edit: Edit::Replace(dedup),
            });
        }
        return Ok(out);
    }
    // NAME is the one argument that is not a flag or a flag's value
    if args.len() != 3 || args[0].starts_with("--") {
        return Err(USAGE.into());
    }
    let name = args[0].clone();
    validate_name(&name)?;
    let edit = if let Some(l) = lanes {
        Edit::Replace(lane_list(l)?)
    } else if let Some(a) = add {
        Edit::Add(nonempty(lane_list(a)?, "--add")?)
    } else {
        Edit::Remove(nonempty(lane_list(remove.unwrap())?, "--remove")?)
    };
    Ok(vec![Change { name, edit }])
}

/// `{"NAME": ["lane", ...], ...}`. ⚠️ A repeated NAME is an error: a plain
/// map would keep the last one silently.
fn parse_file(text: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    struct Pairs;
    impl<'de> serde::de::Visitor<'de> for Pairs {
        type Value = Vec<(String, Vec<String>)>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an object of NAME: [lanes]")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut m: M,
        ) -> Result<Self::Value, M::Error> {
            let mut out: Vec<(String, Vec<String>)> = Vec::new();
            while let Some((k, v)) = m.next_entry::<String, Vec<String>>()? {
                if out.iter().any(|(n, _)| *n == k) {
                    return Err(serde::de::Error::custom(format!("{k} appears twice")));
                }
                out.push((k, v));
            }
            Ok(out)
        }
    }
    use serde::Deserializer;
    serde_json::Deserializer::from_str(text)
        .deserialize_map(Pairs)
        .map_err(|e| e.to_string())
}

pub fn apply(current: &[String], edit: &Edit) -> Vec<String> {
    match edit {
        Edit::Replace(l) => l.clone(),
        Edit::Add(l) => {
            let mut out = current.to_vec();
            for x in l {
                if !out.contains(x) {
                    out.push(x.clone());
                }
            }
            out
        }
        Edit::Remove(l) => current.iter().filter(|x| !l.contains(x)).cloned().collect(),
    }
}

/// The before and after of every change. An unknown entry fails the whole
/// call (nothing is half-applied); so does naming an entry twice.
pub fn plan(vault: &Vault, changes: &[Change]) -> Result<Vec<Planned>, String> {
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for c in changes {
        if seen.contains(&c.name.as_str()) {
            return Err(format!("{} is named twice", c.name));
        }
        seen.push(&c.name);
        let s = vault
            .secrets
            .get(&c.name)
            .ok_or_else(|| format!("no secret named {}", c.name))?;
        out.push(Planned {
            name: c.name.clone(),
            old: s.lanes.clone(),
            new: apply(&s.lanes, &c.edit),
        });
    }
    Ok(out)
}

/// ⚠️ After the person approves, the vault is read again. `--add` and
/// `--remove` are relative, so a vault that changed meanwhile would yield a
/// list nobody saw. Anything but the very plan that was approved is refused.
pub fn same_as_approved(approved: &[Planned], replanned: &[Planned]) -> Result<(), String> {
    if approved == replanned {
        Ok(())
    } else {
        Err("the vault changed while you decided; nothing was written".into())
    }
}

/// Writes the planned lists into the vault.
pub fn commit(vault: &mut Vault, plan: &[Planned]) {
    for p in plan {
        if let Some(s) = vault.secrets.get_mut(&p.name) {
            s.lanes = p.new.clone();
        }
    }
}

fn show(l: &[String]) -> String {
    if l.is_empty() {
        "nobody".into()
    } else {
        l.join(", ")
    }
}

fn clip(s: String) -> String {
    if s.chars().count() <= PROMPT_LIST_CHARS {
        return s;
    }
    let head: String = s.chars().take(PROMPT_LIST_CHARS).collect();
    format!("{head}... ({} chars)", s.chars().count())
}

/// What the person sees. ⚠️ Shows each entry and its NEW list (and the old
/// one): approving a list the approver cannot see would defeat the point.
/// Entries past `PROMPT_ENTRIES` are counted, and the binding covers them.
pub fn prompt_text(plan: &[Planned]) -> Result<String, String> {
    let mut t = format!(
        "with-secret: change which lanes may request {} secret(s)?",
        plan.len()
    );
    // Never clipped, and before the entries (a dialog cuts the tail): every
    // lane that GAINS an entry anywhere in the batch, so a grant on entry 12
    // or past a long list is still seen.
    let mut gained: Vec<&str> = Vec::new();
    for p in plan {
        for l in &p.new {
            if !p.old.contains(l) && !gained.contains(&l.as_str()) {
                gained.push(l);
            }
        }
    }
    let gained = gained.join(", ");
    if gained.chars().count() > MAX_GAINED_CHARS {
        return Err("too many newly allowed lanes to show in one prompt: split the file".into());
    }
    t.push_str(&format!(
        "\nNewly allowed (all entries): {}",
        if gained.is_empty() { "none" } else { &gained }
    ));
    for p in plan.iter().take(PROMPT_ENTRIES) {
        t.push_str(&format!(
            "\n{}: {} -> {}",
            p.name,
            clip(show(&p.old)),
            clip(show(&p.new))
        ));
    }
    if plan.len() > PROMPT_ENTRIES {
        t.push_str(&format!("\n... and {} more", plan.len() - PROMPT_ENTRIES));
    }
    Ok(t)
}

/// Parts for `binding_for`: every entry with its full new list, so a
/// provider that signs signs exactly this set of changes.
pub fn binding_parts(plan: &[Planned]) -> Vec<Vec<u8>> {
    let mut parts = vec![b"allow".to_vec()];
    for p in plan {
        parts.push(
            serde_json::to_vec(&(&p.name, &p.new)).expect("a name and a list always serialise"),
        );
    }
    parts
}

/// Soft problems: a role no state file has, and a role that is not lower-case
/// (only the cwd-leaf fallback lower-cases). Not errors.
pub fn warnings(plan: &[Planned], known_roles: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for p in plan {
        for l in &p.new {
            if l.to_lowercase() != *l {
                out.push(format!(
                    "{}: '{l}' is not lower-case; roles are matched exactly",
                    p.name
                ));
            }
            if !known_roles.contains(l) {
                out.push(format!(
                    "{}: '{l}' matches no lane-state file (typo?)",
                    p.name
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Access, Secret};
    use chrono::Utc;

    fn s(l: &[&str]) -> Vec<String> {
        l.iter().map(|x| x.to_string()).collect()
    }

    fn argv(a: &[&str]) -> Vec<String> {
        s(a)
    }

    fn no_file(_: &str) -> Result<String, String> {
        Err("no file expected".into())
    }

    fn vault(entries: &[(&str, &[&str])]) -> Vault {
        let mut v = Vault::default();
        for (n, l) in entries {
            v.secrets.insert(
                n.to_string(),
                Secret {
                    value: "x".into(),
                    env_var: "E".into(),
                    access: Access::Write,
                    created_at: Utc::now(),
                    rotate_by: None,
                    lanes: s(l),
                },
            );
        }
        v
    }

    #[test]
    fn replace_add_remove_apply_to_a_list() {
        let cur = s(&["pm", "overmind"]);
        assert_eq!(apply(&cur, &Edit::Replace(s(&["x"]))), s(&["x"]));
        assert!(apply(&cur, &Edit::Replace(vec![])).is_empty());
        assert_eq!(
            apply(&cur, &Edit::Add(s(&["pm", "synapse"]))),
            s(&["pm", "overmind", "synapse"])
        );
        assert_eq!(
            apply(&cur, &Edit::Remove(s(&["pm", "nope"]))),
            s(&["overmind"])
        );
    }

    #[test]
    fn one_entry_parses_in_each_mode() {
        let c = parse_args(&argv(&["FOO", "--lanes", "pm,overmind"]), no_file).unwrap();
        assert_eq!(
            c,
            vec![Change {
                name: "FOO".into(),
                edit: Edit::Replace(s(&["pm", "overmind"]))
            }]
        );
        let c = parse_args(&argv(&["FOO", "--lanes", "none"]), no_file).unwrap();
        assert_eq!(c[0].edit, Edit::Replace(vec![]));
        let c = parse_args(&argv(&["FOO", "--add", "pm"]), no_file).unwrap();
        assert_eq!(c[0].edit, Edit::Add(s(&["pm"])));
        let c = parse_args(&argv(&["FOO", "--remove", "pm"]), no_file).unwrap();
        assert_eq!(c[0].edit, Edit::Remove(s(&["pm"])));
    }

    #[test]
    fn bad_arguments_are_refused() {
        for bad in [
            &["FOO"][..],
            &["FOO", "--lanes"],
            &["FOO", "--lanes", "pm", "--add", "x"],
            &["foo", "--lanes", "pm"],
            &["--lanes", "pm", "FOO"],
            &["FOO", "--add", "none"],
            &["FOO", "--remove", "none"],
            &["FOO", "--lanes", "--add"],
            &["FOO", "--lanes", "pm", "extra"],
            &["FOO", "--file", "f.json"],
            &["--file", "f.json", "FOO"],
        ] {
            assert!(
                parse_args(&argv(bad), |_| Ok("{\"A_B\":[]}".into())).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_file_names_several_entries_and_validates_them() {
        let read = |f: &str| {
            assert_eq!(f, "l.json");
            Ok(r#"{"R2_ID":["pm","pm"],"R2_SECRET":["pm"],"PARKED":[]}"#.to_string())
        };
        let c = parse_args(&argv(&["--file", "l.json"]), read).unwrap();
        assert_eq!(c.len(), 3);
        let by = |n: &str| c.iter().find(|x| x.name == n).unwrap().edit.clone();
        assert_eq!(by("R2_ID"), Edit::Replace(s(&["pm"])));
        assert_eq!(by("PARKED"), Edit::Replace(vec![]));
        for bad in [
            "{}",
            "not json",
            r#"{"lower":["pm"]}"#,
            r#"{"FOO":["none"]}"#,
            r#"{"FOO":["a,b"]}"#,
            r#"{"FOO":""}"#,
        ] {
            assert!(
                parse_args(&argv(&["--file", "l.json"]), |_| Ok(bad.to_string())).is_err(),
                "{bad}"
            );
        }
        assert!(parse_args(&argv(&["--file", "l.json"]), |_| Err("unreadable".into())).is_err());
    }

    #[test]
    fn a_plan_is_all_or_nothing() {
        let v = vault(&[("FOO", &["pm"]), ("BAR", &["a"])]);
        let ch = |n: &str, e: Edit| Change {
            name: n.into(),
            edit: e,
        };
        let p = plan(
            &v,
            &[
                ch("FOO", Edit::Add(s(&["x"]))),
                ch("BAR", Edit::Remove(s(&["a"]))),
            ],
        )
        .unwrap();
        assert_eq!(
            p[0],
            Planned {
                name: "FOO".into(),
                old: s(&["pm"]),
                new: s(&["pm", "x"])
            }
        );
        assert!(p[1].new.is_empty());
        assert!(plan(
            &v,
            &[
                ch("FOO", Edit::Add(s(&["x"]))),
                ch("NOPE", Edit::Add(s(&["x"])))
            ]
        )
        .is_err());
        assert!(plan(
            &v,
            &[
                ch("FOO", Edit::Add(s(&["x"]))),
                ch("FOO", Edit::Add(s(&["y"])))
            ]
        )
        .is_err());
    }

    #[test]
    fn commit_changes_lanes_and_nothing_else() {
        let mut v = vault(&[("FOO", &["pm"])]);
        let before = v.secrets["FOO"].clone();
        let p = plan(
            &v,
            &[Change {
                name: "FOO".into(),
                edit: Edit::Replace(s(&["a"])),
            }],
        )
        .unwrap();
        commit(&mut v, &p);
        let mut expect = before;
        expect.lanes = s(&["a"]);
        assert_eq!(v.secrets["FOO"], expect);
    }

    #[test]
    fn the_prompt_shows_the_entry_and_the_new_list() {
        let p = vec![Planned {
            name: "FOO".into(),
            old: s(&["pm"]),
            new: s(&["pm", "overmind"]),
        }];
        let t = prompt_text(&p).unwrap();
        assert!(t.contains("FOO: pm -> pm, overmind"), "{t}");
        assert!(t.contains("Newly allowed (all entries): overmind"), "{t}");
        assert!(!t.contains("allowd"));
        let p = vec![Planned {
            name: "FOO".into(),
            old: s(&["pm"]),
            new: vec![],
        }];
        let t = prompt_text(&p).unwrap();
        assert!(t.contains("-> nobody") && t.contains("Newly allowed (all entries): none"));
    }

    #[test]
    fn a_big_batch_is_counted_not_hidden_and_the_binding_covers_all() {
        let plan: Vec<Planned> = (0..17)
            .map(|i| Planned {
                name: format!("SEC_{i}"),
                old: vec![],
                new: s(&["pm"]),
            })
            .collect();
        let t = prompt_text(&plan).unwrap();
        assert!(t.contains("SEC_0") && t.contains("SEC_7"));
        assert!(!t.contains("SEC_8"));
        assert!(t.contains("... and 9 more"), "{t}");
        let parts = binding_parts(&plan);
        assert_eq!(parts.len(), 18);
        // changing the last entry's list changes the binding
        let mut other = plan.clone();
        other[16].new = s(&["pm", "x"]);
        assert_ne!(parts, binding_parts(&other));
    }

    #[test]
    fn a_long_list_is_cut_with_a_count() {
        let long: Vec<String> = (0..60).map(|i| format!("lane-{i}")).collect();
        let t = prompt_text(&[Planned {
            name: "FOO".into(),
            old: vec![],
            new: long,
        }]);
        // 60 lanes is more than the unclipped line may carry
        assert!(t.is_err());
        let long: Vec<String> = (0..9).map(|i| format!("lane-{i}")).collect();
        let t = prompt_text(&[Planned {
            name: "FOO".into(),
            old: vec![],
            new: long.iter().cloned().chain(["x".repeat(130)]).collect(),
        }])
        .unwrap();
        assert!(t.contains("... ("), "{t}");
    }

    #[test]
    fn a_grant_hidden_past_the_clip_or_past_entry_eight_is_still_shown() {
        let mut plan: Vec<Planned> = (0..12)
            .map(|i| Planned {
                name: format!("SEC_{i}"),
                old: vec![],
                new: s(&["pm"]),
            })
            .collect();
        plan[11].new.push("sneaky".into());
        let t = prompt_text(&plan).unwrap();
        assert!(!t.contains("SEC_11"));
        assert!(t.contains("Newly allowed (all entries): pm, sneaky"), "{t}");
        // exactly 8 entries: no "more" line; 9: one
        assert!(!prompt_text(&plan[..8]).unwrap().contains("more"));
        assert!(prompt_text(&plan[..9]).unwrap().contains("... and 1 more"));
        // a lane that only keeps its access is not "newly allowed"
        let kept = [Planned {
            name: "FOO".into(),
            old: s(&["pm"]),
            new: s(&["pm"]),
        }];
        assert!(prompt_text(&kept).unwrap().contains("(all entries): none"));
    }

    #[test]
    fn control_characters_and_padding_cannot_forge_prompt_lines() {
        let evil = r#"{"FOO":["a\nSEC_9: pm -> pm"]}"#;
        assert!(parse_args(&argv(&["--file", "f"]), |_| Ok(evil.into())).is_err());
        let padded = r#"{"FOO":[" pm"]}"#;
        assert!(parse_args(&argv(&["--file", "f"]), |_| Ok(padded.into())).is_err());
        assert!(parse_args(&argv(&["FOO", "--lanes", "a\nb"]), no_file).is_err());
        let p = [Planned {
            name: "FOO".into(),
            old: vec![],
            new: s(&["a", "b"]),
        }];
        assert_eq!(prompt_text(&p).unwrap().lines().count(), 3);
    }

    #[test]
    fn a_repeated_name_in_a_file_is_refused() {
        let dup = r#"{"FOO":["pm"],"FOO":["x"]}"#;
        let e = parse_args(&argv(&["--file", "f"]), |_| Ok(dup.into())).unwrap_err();
        assert!(e.contains("appears twice"), "{e}");
    }

    #[test]
    fn only_the_approved_plan_may_be_written() {
        let before = vault(&[("FOO", &["pm"])]);
        let add = [Change {
            name: "FOO".into(),
            edit: Edit::Add(s(&["x"])),
        }];
        let approved = plan(&before, &add).unwrap();
        assert!(same_as_approved(&approved, &plan(&before, &add).unwrap()).is_ok());
        // `vault set` rewrote the list between the Hello and the save
        let after = vault(&[("FOO", &["pm", "evil"])]);
        assert!(same_as_approved(&approved, &plan(&after, &add).unwrap()).is_err());
    }

    #[test]
    fn unknown_and_upper_case_roles_warn() {
        let p = vec![Planned {
            name: "FOO".into(),
            old: vec![],
            new: s(&["pm", "Typo", "ghost"]),
        }];
        let w = warnings(&p, &s(&["pm", "Typo"]));
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w.iter().any(|x| x.contains("not lower-case")));
        assert!(w
            .iter()
            .any(|x| x.contains("'ghost' matches no lane-state file")));
    }
}
