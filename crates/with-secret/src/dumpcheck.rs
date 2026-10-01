// SPDX-License-Identifier: MIT OR Apache-2.0
//! Is this an environment dump? Item 81 (d). ⚠️ A pattern check for ACCIDENTS -
//! the 2026-09-28 incident was a bare `env`. It is trivially bypassed on
//! purpose (`python -c ...`), and is not the gate; the vault is.

const DOTENV_SAFE_SUFFIXES: [&str; 3] = [".example", ".sample", ".template"];

fn is_dotenv(path: &str) -> bool {
    let base = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .trim_matches(['"', '\'']);
    (base == ".env" || base.starts_with(".env."))
        && !DOTENV_SAFE_SUFFIXES.iter().any(|s| base.ends_with(s))
}

fn image(token: &str) -> String {
    let base = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_string()
}

fn segments(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
        if two == "&&" || two == "||" {
            out.push(std::mem::take(&mut cur));
            i += 2;
            continue;
        }
        if c == '|' || c == ';' || c == '\n' {
            out.push(std::mem::take(&mut cur));
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    out.push(cur);
    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn command_dump_reason(cmd: &str) -> Option<String> {
    if cmd
        .to_ascii_lowercase()
        .contains("[environment]::getenvironmentvariables")
    {
        return Some("lists every environment variable".into());
    }
    for seg in segments(cmd) {
        let toks: Vec<&str> = seg.split_whitespace().collect();
        let Some(first) = toks.first() else { continue };
        let rest = &toks[1..];
        let name = image(first);
        let blocked = match name.as_str() {
            "env" => !rest.iter().any(|t| !t.starts_with('-') && !t.contains('=')),
            "printenv" => true,
            "set" | "export" | "declare" | "typeset" => {
                rest.is_empty() || rest.iter().all(|t| *t == "-p" || *t == "-x")
            }
            "get-childitem" | "gci" | "ls" | "dir" | "get-item" | "gi" => rest.iter().any(|t| {
                t.trim_matches(['"', '\''])
                    .to_ascii_lowercase()
                    .starts_with("env:")
            }),
            "cat" | "type" | "gc" | "get-content" | "more" | "less" | "head" | "tail" | "bat" => {
                rest.iter().any(|t| is_dotenv(t))
            }
            "cmd"
                if rest.first().is_some_and(|f| {
                    f.eq_ignore_ascii_case("/c") || f.eq_ignore_ascii_case("/k")
                }) =>
            {
                if let Some(r) = command_dump_reason(&rest[1..].join(" ")) {
                    return Some(r);
                }
                false
            }
            "bash" | "sh" | "pwsh" | "powershell"
                if rest.first().is_some_and(|f| {
                    let f = f.to_ascii_lowercase();
                    f == "-c" || f == "-command"
                }) =>
            {
                let inner = rest[1..].join(" ");
                if let Some(r) = command_dump_reason(inner.trim_matches(['"', '\''])) {
                    return Some(r);
                }
                false
            }
            _ => false,
        };
        if blocked {
            return Some(format!(
                "`{seg}` would print environment variables or a .env file"
            ));
        }
    }
    None
}

pub fn dump_reason(tool_name: &str, input: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Bash" | "PowerShell" => command_dump_reason(input.get("command")?.as_str()?),
        "Read" => {
            let p = input.get("file_path")?.as_str()?;
            is_dotenv(p).then(|| format!("{p} is a .env file"))
        }
        _ => None,
    }
    .map(|why| {
        format!(
            "with-secret hook: blocked - {why}. Secrets are not read from the \
                        environment here; use `with-secret NAME --reason ... -- <command>`."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bash(c: &str) -> Option<String> {
        dump_reason("Bash", &json!({"command": c}))
    }
    fn ps(c: &str) -> Option<String> {
        dump_reason("PowerShell", &json!({"command": c}))
    }

    #[test]
    fn env_dumps_are_blocked() {
        for c in [
            "env",
            "env | sort",
            "cd x && env",
            "printenv",
            "printenv PATH",
            "set",
            "export",
            "export -p",
            "declare -x",
            "/usr/bin/env",
            "cmd /c set",
            "bash -c \"env\"",
            "npm run check; env",
            "cmd /c echo hi; env",
        ] {
            assert!(bash(c).is_some(), "{c:?} was allowed");
        }
        for c in [
            "Get-ChildItem env:",
            "gci Env:\\",
            "ls env:*",
            "dir env:",
            "Get-Item env:*",
            "[Environment]::GetEnvironmentVariables()",
            "pwsh -Command \"Get-ChildItem env:\"",
        ] {
            assert!(ps(c).is_some(), "{c:?} was allowed");
        }
    }

    #[test]
    fn ordinary_commands_pass() {
        for c in [
            "env FOO=1 cargo test",
            "env -u HOME ls",
            "cargo test",
            "git status",
            "echo $PATH",
            "set -o pipefail && cargo test",
            "grep -n env src/main.rs",
            "cat README.md",
            "cat .env.example",
        ] {
            assert!(bash(c).is_none(), "{c:?} was blocked");
        }
        for c in ["$env:PATH", "Get-ChildItem src", "Get-Content README.md"] {
            assert!(ps(c).is_none(), "{c:?} was blocked");
        }
    }

    #[test]
    fn dotenv_reads_are_blocked() {
        assert!(bash("cat .env").is_some());
        assert!(bash("cat apps/api/.env.local").is_some());
        assert!(ps("Get-Content .env").is_some());
        assert!(ps("type C:\\x\\.env.production").is_some());
        assert!(dump_reason("Read", &json!({"file_path": "C:\\Projects\\X\\.env"})).is_some());
        assert!(dump_reason(
            "Read",
            &json!({"file_path": "C:\\Projects\\X\\.env.sample"})
        )
        .is_none());
        assert!(dump_reason(
            "Read",
            &json!({"file_path": "C:\\Projects\\X\\src\\env.rs"})
        )
        .is_none());
    }

    #[test]
    fn other_tools_and_bad_input_pass() {
        assert!(dump_reason("Write", &json!({"file_path": ".env"})).is_none());
        assert!(dump_reason("Bash", &json!({})).is_none());
    }
}
