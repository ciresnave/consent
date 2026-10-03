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

/// A command word's program: quotes, a leading backslash, the directory and
/// `.exe` removed, lowercased. `"printenv"`, `\printenv` and
/// `/usr/bin/printenv` all run `printenv`.
fn image(token: &str) -> String {
    let token = token.trim_matches(['"', '\'']).trim_start_matches('\\');
    let base = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_string()
}

/// `NAME=VALUE` before a command sets a variable; the command comes after it.
fn is_assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Words a POSIX shell reads before the command itself: `{ printenv; }`,
/// `if x; then printenv; fi`, `! printenv`.
const RESERVED: [&str; 10] = [
    "{", "}", "!", "if", "then", "else", "elif", "do", "while", "until",
];

/// Where the command word is: past `NAME=VALUE` prefixes and reserved words.
fn command_start(toks: &[&str]) -> Option<usize> {
    toks.iter()
        .position(|t| !is_assignment(t) && !RESERVED.contains(t))
}

/// `<`, `>`, `2>`, `>>`, `&>` and `<file` style redirections.
fn is_redirect(token: &str) -> bool {
    token
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
        .starts_with(['<', '>'])
}

/// The command a wrapper (`env`, `sudo`, `xargs`, ...) runs: its first word
/// that is not an option, a redirection or - as `env` itself reads it, so
/// `env .x=1` still only sets a variable - anything containing `=`.
fn wrapped_command(args: &[&str]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let t = args[i];
        if is_redirect(t) {
            // a bare operator (`<`, `2>`) takes the next word as its target
            let bare = t
                .chars()
                .all(|c| matches!(c, '<' | '>' | '&') || c.is_ascii_digit());
            i += if bare { 2 } else { 1 };
        } else if t.starts_with('-') || t.contains('=') {
            i += 1;
        } else {
            return Some(args[i..].join(" "));
        }
    }
    None
}

/// Programs that run a string, an argument list or their stdin as a command.
/// A quoted string anywhere in a command line that has one of these may be
/// code, so quotes are not trusted there (`quotes_are_trusted`).
const EVALUATORS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "busybox",
    "pwsh",
    "powershell",
    "cmd",
    "wsl",
    "env",
    "eval",
    "exec",
    "command",
    "builtin",
    "nohup",
    "time",
    "nice",
    "sudo",
    "doas",
    "su",
    "runuser",
    "xargs",
    "parallel",
    "ssh",
    "timeout",
    "watch",
    "stdbuf",
    "setsid",
    "flock",
    "chroot",
    "unshare",
    "nsenter",
    "script",
    "expect",
    "screen",
    "tmux",
    "strace",
    "ltrace",
    "iex",
    "invoke-expression",
    "start-process",
    "invoke-command",
    "start-job",
    "start-threadjob",
    "start",
];

/// Evaluators only as the command word: `. file`, `source file` and
/// `trap '...' EXIT` run code, while `find .` or `git add .` do not.
const COMMAND_EVALUATORS: &[&str] = &[".", "source", "trap"];

/// Programs that run the rest of their own command line as a command.
const WRAPPERS: [&str; 15] = [
    "eval",
    "exec",
    "command",
    "builtin",
    "nohup",
    "time",
    "nice",
    "sudo",
    "doas",
    "xargs",
    "iex",
    "invoke-expression",
    "timeout",
    "watch",
    "start-process",
];

/// The quote-unaware split, exactly as before 0.5.4: `|`, `;`, `&&`, `||` and
/// newline all count, quoted or not. ⚠️ Keep it exactly this: it is the
/// fallback, and it denies everything the pre-0.5.4 check denied only while
/// it splits no more and no less. A wider split can cut a command off from
/// its own arguments (`cat } x .env`, where a POSIX `}` is an argument) and
/// cut quoted text into false dumps (`{ $_ -match 'a|set' }`).
fn loose_segments(cmd: &str) -> Vec<String> {
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
        if matches!(c, '|' | ';' | '\n') {
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

fn loose_reason(cmd: &str) -> Option<String> {
    loose_segments(cmd).iter().find_map(|s| segment_reason(s))
}

/// Is this one command (no separators left) an environment dump? Read from
/// its command word (`command_start`) and, as before 0.5.4, from its first
/// word, so that it denies at least everything the pre-0.5.4 check did.
fn segment_reason(seg: &str) -> Option<String> {
    let all: Vec<&str> = seg.split_whitespace().collect();
    let start = command_start(&all);
    start
        .and_then(|s| reason_from(seg, &all[s..]))
        .or_else(|| (start != Some(0)).then(|| reason_from(seg, &all)).flatten())
}

fn reason_from(seg: &str, toks: &[&str]) -> Option<String> {
    let first = *toks.first()?;
    let rest = &toks[1..];
    let name = image(first);
    let blocked = match name.as_str() {
        "env" => match wrapped_command(rest) {
            None => true,
            Some(cmd) => return loose_reason(&cmd),
        },
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
            if rest
                .first()
                .is_some_and(|f| f.eq_ignore_ascii_case("/c") || f.eq_ignore_ascii_case("/k")) =>
        {
            return loose_reason(rest[1..].join(" ").trim_matches(['"', '\'']));
        }
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "pwsh" | "powershell"
            if rest.first().is_some_and(|f| {
                let f = f.to_ascii_lowercase();
                f == "-c" || f == "-command"
            }) =>
        {
            return loose_reason(rest[1..].join(" ").trim_matches(['"', '\'']));
        }
        w if WRAPPERS.contains(&w) => {
            return wrapped_command(rest).and_then(|cmd| loose_reason(&cmd));
        }
        _ => false,
    };
    blocked.then(|| format!("`{seg}` would print environment variables or a .env file"))
}

fn lists_all_variables(cmd: &str) -> bool {
    cmd.to_ascii_lowercase()
        .contains("[environment]::getenvironmentvariables")
}

/// For `with-secret run`: its child's argv joined with spaces, which has
/// already lost its quoting, so every separator counts (`loose_segments`).
pub fn command_dump_reason(cmd: &str) -> Option<String> {
    if lists_all_variables(cmd) {
        return Some("lists every environment variable".into());
    }
    loose_reason(cmd)
}

/// Which shell parses a hook's command; it decides what quotes and escapes
/// mean (`\` in POSIX shells, a backtick in PowerShell).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    Posix,
    PowerShell,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Code,
    /// `( ... )`, `$( ... )`, `@( ... )`: code, ended by `)`.
    Sub,
    /// PowerShell `{ ... }` script block, or a bash 5.3 `${ ...; }` /
    /// `${| ...; }` command substitution: code, ended by `}`.
    Block,
    Single,
    /// POSIX `$'...'`, where `\` escapes.
    AnsiC,
    Double,
    /// PowerShell `@'` here-string, ended by `'@` at the start of a line.
    HereSingle,
    /// PowerShell `@"` here-string, ended by `"@` at the start of a line.
    HereDouble,
}

/// PowerShell reads U+2018-U+201B as single quotes and U+201C-U+201E as
/// double quotes, even to close an ASCII-opened string.
fn is_smart_quote(c: char) -> bool {
    ('\u{2018}'..='\u{201E}').contains(&c)
}

/// POSIX backtick body as the inner shell sees it: `` \` ``, `\\` and `\$`
/// lose their backslash; every other backslash stays.
fn unescape_backticks(body: &[char]) -> String {
    let mut out = String::new();
    let mut k = 0;
    while k < body.len() {
        if body[k] == '\\' && matches!(body.get(k + 1), Some('`' | '\\' | '$')) {
            out.push(body[k + 1]);
            k += 2;
        } else {
            out.push(body[k]);
            k += 1;
        }
    }
    out
}

/// The commands `shell` would run, honouring its quotes and comments.
///
/// Code nested in a command - `$(...)`, `(...)`, POSIX backticks, bash 5.3
/// `${ ...; }`, a PowerShell `{ ... }` block, even inside double quotes -
/// comes out as commands of its own, AND its text stays in the command
/// around it, because its output or the block itself can be that command's
/// argument (`ls $(echo env:)`, `ls { env: }`). The one exception is a bare
/// `(` where a command starts, a subshell or group, which leaves nothing.
///
/// `None` when the text cannot be followed to the end (an unterminated
/// quote, substitution, block or block comment, or an unmatched `)` or
/// PowerShell `}`), or uses something not modelled here (a bash heredoc,
/// PowerShell's `--%`, `${...}` or smart quotes), or where it is unsure
/// whether a comment or here-string starts. The caller then falls back to
/// `loose_reason`.
fn shell_segments(cmd: &str, shell: Shell) -> Option<Vec<String>> {
    let c: Vec<char> = cmd.chars().collect();
    let at = |i: usize, s: &str| {
        s.chars()
            .enumerate()
            .all(|(k, ch)| c.get(i + k) == Some(&ch))
    };
    let posix = shell == Shell::Posix;
    let esc = if posix { '\\' } else { '`' };
    // Not modelled: after `--%` the rest of the line is passed on as it is;
    // `${...}` is a variable whose name may hold quotes; smart quotes.
    if !posix && (cmd.contains("--%") || cmd.contains("${") || c.iter().any(|&x| is_smart_quote(x)))
    {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    // One buffer per open code context: the outer command keeps building
    // while nested code's own commands are collected separately.
    let mut curs: Vec<String> = vec![String::new()];
    let mut stack: Vec<Mode> = vec![Mode::Code];
    // Per open Sub / Block: where its text starts, to copy into the command
    // around it when it closes (`None`: copy nothing).
    let mut opens: Vec<Option<usize>> = Vec::new();
    // ⚠️ Is the next character at the start of a word? A `#` (and a
    // PowerShell `<#` or here-string) only means something there, and
    // misreading one pairs its quotes with later ones and can hide real code.
    // `Some` only where the rule was checked against bash 5.3 / pwsh 7;
    // `None` (unsure) makes a `#`, `<#` or here-string give the parse up.
    //
    //   after ...                     bash         pwsh
    //   start, whitespace, newline    Some(true)   Some(true)
    //   `;`                           Some(true)   Some(true)
    //   `|`, `&`, `&&`, `||`          Some(true)   None
    //   `<`, `>`                      Some(true)   None
    //   `(` / `$(` / `${ ` opening    Some(true)   None
    //   a bare subshell's `)`         Some(true)   None
    //   a substitution's `)`/`}`/`` ` `` Some(false)  None
    //   a quote (once closed)         Some(false)  None
    //   an escaped character          Some(false)  Some(false)
    //   a word character              Some(false)  Some(false) (alnum, `_`)
    //   any other character           Some(false)  None
    //   a continuation (removed)      unchanged    unchanged
    let mut word_start: Option<bool> = Some(true);
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let mode = *stack.last()?;
        // Line continuation is removed outright, so `ls \`, newline,
        // `declare` runs `declare`: POSIX `\` + newline outside single
        // quotes, PowerShell backtick + newline in code.
        let continues = if posix {
            ch == '\\' && !matches!(mode, Mode::Single | Mode::AnsiC)
        } else {
            ch == '`' && matches!(mode, Mode::Code | Mode::Sub | Mode::Block)
        };
        if continues && (at(i + 1, "\n") || at(i + 1, "\r\n")) {
            i += if c.get(i + 1) == Some(&'\n') { 2 } else { 3 };
            continue;
        }
        let code = matches!(mode, Mode::Code | Mode::Sub | Mode::Block);
        let in_double = matches!(mode, Mode::Double | Mode::HereDouble);

        // ⚠️ Nested code opens here, BEFORE `cur` is borrowed below, and in
        // both code and double-quote modes: these two branches push their
        // own buffers and `continue`.
        //
        // POSIX backticks: bash finds the closing backtick without regard
        // to quotes, then runs the body as a script of its own.
        if posix && ch == '`' && (code || in_double) {
            let mut k = i + 1;
            while k < c.len() && c[k] != '`' {
                k += if c[k] == '\\' { 2 } else { 1 };
            }
            if k >= c.len() {
                return None;
            }
            out.extend(shell_segments(&unescape_backticks(&c[i + 1..k]), shell)?);
            curs.last_mut()?.extend(&c[i..=k]);
            word_start = Some(false);
            i = k + 1;
            continue;
        }

        // opening nested code: the same in code and in double quotes
        let opens_sub = ch == '$' && c.get(i + 1) == Some(&'(');
        let opens_funsub = posix
            && ch == '$'
            && c.get(i + 1) == Some(&'{')
            && c.get(i + 2).is_some_and(|n| n.is_whitespace() || *n == '|');
        if (code || in_double) && (opens_sub || opens_funsub) {
            opens.push(Some(i));
            curs.push(String::new());
            stack.push(if opens_sub { Mode::Sub } else { Mode::Block });
            word_start = if posix { Some(true) } else { None };
            i += 2;
            continue;
        }

        let cur = curs.last_mut()?;
        match mode {
            Mode::Single => {
                cur.push(ch);
                if ch == '\'' {
                    if !posix && c.get(i + 1) == Some(&'\'') {
                        cur.push('\'');
                        i += 2;
                        continue;
                    }
                    stack.pop();
                }
                i += 1;
            }
            Mode::AnsiC => {
                cur.push(ch);
                if ch == '\\' {
                    cur.extend(c.get(i + 1));
                    i += 2;
                    continue;
                }
                if ch == '\'' {
                    stack.pop();
                }
                i += 1;
            }
            Mode::HereSingle => {
                // a line ends at `\n` or a lone `\r`; `'@` must open it
                if matches!(ch, '\n' | '\r') && at(i + 1, "'@") {
                    cur.push_str("\n'@");
                    stack.pop();
                    i += 3;
                } else {
                    cur.push(ch);
                    i += 1;
                }
            }
            Mode::Double | Mode::HereDouble => {
                if ch == esc {
                    cur.push(ch);
                    cur.extend(c.get(i + 1));
                    i += 2;
                } else if mode == Mode::Double && ch == '"' {
                    cur.push('"');
                    if !posix && c.get(i + 1) == Some(&'"') {
                        cur.push('"');
                        i += 2;
                    } else {
                        stack.pop();
                        i += 1;
                    }
                } else if mode == Mode::HereDouble && matches!(ch, '\n' | '\r') && at(i + 1, "\"@")
                {
                    cur.push_str("\n\"@");
                    stack.pop();
                    i += 3;
                } else {
                    cur.push(ch);
                    i += 1;
                }
            }
            Mode::Code | Mode::Sub | Mode::Block => {
                // closing nested code: its last command comes out, and its
                // text goes back into the command around it
                let closes = match mode {
                    Mode::Sub => ch == ')',
                    Mode::Block => ch == '}',
                    _ => false,
                };
                if closes {
                    out.extend(curs.pop());
                    stack.pop();
                    let start = opens.pop()?;
                    if let Some(start) = start {
                        curs.last_mut()?.extend(&c[start..=i]);
                    }
                    // a substitution's text continues the word; after a bare
                    // subshell's `)` a word starts (bash)
                    word_start = match (posix, start) {
                        (true, Some(_)) => Some(false),
                        (true, None) => Some(true),
                        (false, _) => None,
                    };
                    i += 1;
                    continue;
                }
                let here_header = !posix && {
                    let q = c.get(i + 1);
                    let mut k = i + 2;
                    while matches!(c.get(k), Some(' ' | '\t')) {
                        k += 1;
                    }
                    ch == '@'
                        && matches!(q, Some('\'' | '"'))
                        && (c.get(k) == Some(&'\n') || at(k, "\r\n"))
                };
                if ch == esc {
                    cur.push(ch);
                    cur.extend(c.get(i + 1));
                    word_start = Some(false);
                    i += 2;
                } else if posix && at(i, "<<") && !at(i, "<<<") && (i == 0 || c[i - 1] != '<') {
                    // A heredoc's body is data whose quotes do not pair with
                    // the code's, and an unquoted one runs `$(...)`. Not
                    // modelled.
                    return None;
                } else if ch == '#' || (!posix && at(i, "<#")) {
                    if !word_start? {
                        cur.push(ch);
                        word_start = Some(false);
                        i += 1;
                    } else if ch == '#' {
                        // a comment runs to the end of the line, quotes and all
                        while i < c.len() && c[i] != '\n' && (posix || c[i] != '\r') {
                            i += 1;
                        }
                    } else {
                        // a PowerShell block comment runs to `#>`
                        i += 2;
                        while i < c.len() && !at(i, "#>") {
                            i += 1;
                        }
                        if i >= c.len() {
                            return None;
                        }
                        i += 2;
                        word_start = None;
                    }
                } else if here_header {
                    if !word_start? {
                        cur.push(ch);
                        word_start = None;
                        i += 1;
                    } else {
                        let single = c[i + 1] == '\'';
                        cur.push_str(if single { "@'" } else { "@\"" });
                        stack.push(if single {
                            Mode::HereSingle
                        } else {
                            Mode::HereDouble
                        });
                        word_start = None;
                        i += 2;
                    }
                } else if posix && ch == '$' && c.get(i + 1) == Some(&'\'') {
                    cur.push_str("$'");
                    stack.push(Mode::AnsiC);
                    word_start = Some(false);
                    i += 2;
                } else if ch == '\'' || ch == '"' {
                    cur.push(ch);
                    stack.push(if ch == '\'' {
                        Mode::Single
                    } else {
                        Mode::Double
                    });
                    // a closed quote leaves bash mid-word; pwsh: unchecked
                    word_start = if posix { Some(false) } else { None };
                    i += 1;
                } else if ch == '(' {
                    // a bare `(` where a command starts is a subshell or
                    // group: nothing of it stays in the (empty) command
                    opens.push((!cur.trim().is_empty()).then_some(i));
                    curs.push(String::new());
                    stack.push(Mode::Sub);
                    word_start = if posix { Some(true) } else { None };
                    i += 1;
                } else if !posix && ch == '{' {
                    opens.push(Some(i));
                    curs.push(String::new());
                    stack.push(Mode::Block);
                    word_start = None;
                    i += 1;
                } else if ch == ')' || (!posix && ch == '}') {
                    return None; // unmatched
                } else if at(i, "&&") || at(i, "||") {
                    out.push(std::mem::take(cur));
                    word_start = if posix { Some(true) } else { None };
                    i += 2;
                } else if ch == '&'
                    && ((i > 0 && matches!(c[i - 1], '<' | '>')) || c.get(i + 1) == Some(&'>'))
                {
                    // `>&2`, `2>&1`, `<&3`, `&>file`: part of a redirection
                    cur.push(ch);
                    word_start = Some(false);
                    i += 1;
                } else if matches!(ch, '|' | ';' | '\n' | '&') {
                    // POSIX `{`/`}` are reserved words, special only where a
                    // command starts (`command_start`); elsewhere they are
                    // plain arguments.
                    out.push(std::mem::take(cur));
                    word_start = if posix || matches!(ch, ';' | '\n') {
                        Some(true)
                    } else {
                        None
                    };
                    i += 1;
                } else {
                    cur.push(ch);
                    word_start = if ch.is_whitespace() || (posix && matches!(ch, '<' | '>')) {
                        Some(true)
                    } else if posix || ch.is_ascii_alphanumeric() || ch == '_' {
                        Some(false)
                    } else {
                        None
                    };
                    i += 1;
                }
            }
        }
    }
    if stack.len() != 1 {
        return None;
    }
    out.extend(curs.pop());
    Some(
        out.into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

/// Would an option make the program run a string as a command
/// (`find -exec`, `git rebase --exec`, `--pager=...`, `--editor`)?
fn runs_code_option(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    w.starts_with('-')
        && !w.starts_with("--no-")
        && [
            "exec", "-ok", "pager", "extcmd", "editor", "shell", "command",
        ]
        .iter()
        .any(|k| w.contains(k))
}

/// May this command's quotes be trusted? Only when its command word is a
/// plain, fixed program name - not a variable or a substitution, whatever
/// it expands to is unknown - that does not run a string as code itself
/// (`COMMAND_EVALUATORS`), when no word in it names an evaluator - which
/// covers one passed as an argument (`find . -exec sh -c '...'`) - and no
/// option makes the program run a string (`runs_code_option`, git's `-c`,
/// `-x`, `-O`). A PowerShell string or here-string as a pipeline's first
/// element is a value, not a command.
fn quotes_are_trusted(seg: &str, shell: Shell) -> bool {
    let toks: Vec<&str> = seg.split_whitespace().collect();
    let Some(first) = command_start(&toks).map(|i| toks[i]) else {
        return true;
    };
    if shell == Shell::PowerShell && (first.starts_with("@'") || first.starts_with("@\"")) {
        return true;
    }
    let word = first.trim_matches(['"', '\'']);
    let fixed = !word.is_empty()
        && word.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '\\' | ':' | '+' | '-')
        });
    let name = image(first);
    let all = words(seg, shell);
    fixed
        && !COMMAND_EVALUATORS.contains(&name.as_str())
        && !all.iter().any(|w| EVALUATORS.contains(&image(w).as_str()))
        && !all.iter().any(|w| runs_code_option(w))
        && !(name == "git"
            && all
                .iter()
                .any(|w| matches!(w.as_str(), "-c" | "-x") || w.starts_with("-O")))
}

/// A command's words as its shell reads them: split at whitespace outside
/// quotes, with quotes and escapes removed - so `"sh"` and `$'sh'` are the
/// word `sh`, and `"x | env"` is one word, not `env`. Inside POSIX double
/// quotes `\` escapes only `$`, a backtick, `"`, `\` and newline.
fn words(seg: &str, shell: Shell) -> Vec<String> {
    let posix = shell == Shell::Posix;
    let esc = if posix { '\\' } else { '`' };
    let mut out = Vec::new();
    let mut cur = String::new();
    // `'` single, `"` double, `$` POSIX `$'...'` (where `\` escapes).
    let mut quote: Option<char> = None;
    let mut chars = seg.chars().peekable();
    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch != '\'' {
                    cur.push(ch);
                } else if !posix && chars.peek() == Some(&'\'') {
                    cur.push('\'');
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some('$') => match ch {
                '\\' => cur.extend(chars.next()),
                '\'' => quote = None,
                _ => cur.push(ch),
            },
            Some(_) => {
                if ch == esc
                    && (!posix || matches!(chars.peek(), Some('$' | '`' | '"' | '\\' | '\n')))
                {
                    cur.extend(chars.next());
                } else if ch == '"' {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == esc {
                    cur.extend(chars.next());
                } else if posix && ch == '$' && matches!(chars.peek(), Some('\'') | Some('"')) {
                    quote = if chars.next() == Some('\'') {
                        Some('$')
                    } else {
                        Some('"')
                    };
                } else if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                } else if ch.is_whitespace() {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// For the hook: `cmd` as the tool's own shell parses it. The commands the
/// parse finds are always checked, as written and with their quotes and
/// escapes removed (`pr\intenv` runs `printenv`). Quotes are honoured -
/// `git grep -E 'a|printenv|b'` is one `git` command and nothing more - only
/// when the quoting can be followed and every command is trusted
/// (`quotes_are_trusted`); otherwise the pre-0.5.4 quote-unaware check is
/// applied as well.
pub fn shell_dump_reason(cmd: &str, shell: Shell) -> Option<String> {
    if lists_all_variables(cmd) {
        return Some("lists every environment variable".into());
    }
    let segs = shell_segments(cmd, shell);
    let parsed = segs
        .iter()
        .flatten()
        .find_map(|s| segment_reason(s).or_else(|| segment_reason(&words(s, shell).join(" "))));
    if parsed.is_some() {
        return parsed;
    }
    match segs {
        Some(segs) if segs.iter().all(|s| quotes_are_trusted(s, shell)) => None,
        _ => loose_reason(cmd),
    }
}

pub fn dump_reason(tool_name: &str, input: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Bash" => shell_dump_reason(input.get("command")?.as_str()?, Shell::Posix),
        "PowerShell" => shell_dump_reason(input.get("command")?.as_str()?, Shell::PowerShell),
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

    // -- quote-aware splitting (PM task, 2026-10-03) ----------------------- //
    //
    // A `|` or `;` inside quotes is not a separator, so a search pattern such
    // as `'a|printenv|b'` is not a dump. ⚠️ SECURITY: quotes are honoured only
    // when nothing in the command could run a quoted string as code; every
    // case below that is expected to DENY is a bypass attempt that must keep
    // failing.

    #[test]
    fn quoted_separators_in_ordinary_commands_pass() {
        for c in [
            "git grep -E 'a|printenv|b'",
            "git grep -n -i -E 'fail.?open|printenv|x' origin/main -- crates",
            "grep -E \"env|set\" src",
            "rg 'printenv|export' -n",
            "echo 'a;printenv'",
            "echo \"x | env\"",
            "git commit -m \"fix: env | set; export\"",
            "echo 'x' && cargo test",
            "cat 'notes.txt' | grep 'env|set'",
            "git commit -m \"use bash | sh here\"",
            // a continuation joins the lines: this is `ls set`
            "ls \\\n set",
            "cat <<< 'a|printenv'",
            "git --no-pager grep -E 'a|printenv'",
            "echo 'a'#'b|printenv'",
            "echo ${#x}",
            "echo a#b",
            "git grep 'a|printenv' # look for both",
            "echo \"$(date)\" | grep 'env|set'",
        ] {
            assert!(bash(c).is_none(), "{c:?} was blocked");
        }
        for c in [
            "Select-String -Pattern 'env:|printenv' file.txt",
            "Write-Output \"Get-ChildItem env:\"",
            "Write-Output 'a;gci env:'",
            "Write-Output 'it''s; gci env:'",
            "Write-Output \"a`\" ; gci env:\"",
            "@'\nGet-ChildItem env:\n'@ | Out-File notes.txt",
            // a here-string on its own is a value; PowerShell prints it
            "@'\nset\n'@",
            "Get-Process | Where-Object { $_.Name -match 'env|set' }",
        ] {
            assert!(ps(c).is_none(), "{c:?} was blocked");
        }
    }

    #[test]
    fn real_dumps_still_deny_around_quotes() {
        for c in [
            // a separator outside quotes
            "echo a | printenv",
            "\"echo a\" ; printenv",
            "echo 'x'|env",
            "echo 'a|b' | env",
            "git grep foo && printenv",
            "echo 'x' & printenv",
            // an escaped quote is not a quote
            "echo \\\"a|printenv",
            "echo \"a\\\"\" ; printenv",
            // ANSI-C quoting
            "echo $'a\\'' ; printenv",
            // substitution runs code, even inside double quotes
            "echo $(printenv)",
            "echo \"$(printenv)\"",
            "echo `printenv`",
            "echo \"`printenv`\"",
            "echo \"$(echo 'x' | printenv)\"",
            "cat <(printenv)",
            "(printenv)",
            "{ printenv; }",
            // bash 5.3 runs `${ cmd; }` and `${| cmd; }`
            "echo ${ printenv; }",
            "echo \"${ printenv; }\"",
            "echo ${| printenv; }",
            // a substitution's output is the outer command's argument
            "ls $(echo env:)",
            "cat `echo x` .env",
            "cat $(echo .env) .env",
            // a quote inside a comment is not a quote
            "echo 1 # '\nprintenv\n#'",
            "echo 1;# '\nprintenv\n#'",
            // `${#x}` is a length, not a comment
            "echo ${#x} ; printenv",
            // a heredoc body's quote is data, and its `$(...)` runs
            "cat <<EOF\nx'\nEOF\nprintenv\necho '",
            "cat <<-EOF\n\tx'\n\tEOF\nprintenv\necho '",
            "cat <<'EOF'\nx'\nEOF\nprintenv\necho '",
            // the command word itself disguised
            "\"printenv\"",
            "'env'",
            "\\printenv",
            "A=1 printenv",
            // something that runs a quoted string as code
            "bash -c 'echo a | printenv'",
            "sh -c \"x; printenv\"",
            "\"bash\" -c 'x;printenv '",
            "echo 'a; printenv ' | bash",
            "eval 'x; printenv'",
            "eval printenv",
            "sudo printenv",
            "nohup printenv",
            "echo x | xargs printenv",
            "$(which bash) -c 'a;printenv '",
            "$SHELL -c 'a;printenv '",
            "find . -exec sh -c 'x; printenv ' \\;",
            "find . -exec \"sh\" -c 'x; printenv ' \\;",
            "find . -exec $'sh' -c 'x; printenv ' \\;",
            "find . -exec s\\h -c 'x; printenv ' \\;",
            // an unterminated quote fails closed to the old split
            "echo 'unterminated | printenv",
            "echo \"unterminated ; printenv",
            "echo `unterminated ; printenv",
            "echo $(unterminated ; printenv",
            // found by differential fuzzing against the pre-0.5.4 check:
            // `env` reads every word with `=` as an assignment
            "env .envA=1",
            "env $SHELLA=1",
            "env =",
            "env < /dev/null",
            "env 2> err.txt",
            // a line continuation is removed, not kept as a word
            "\\\n declare",
            "x;\\\nprintenv",
            "pr\\\nintenv",
            "pr\\\r\nintenv",
            // a POSIX `}` outside command position is a plain argument
            "cat } \\' .env",
            "ls x} env:",
            // reserved words before the command
            "if true; then printenv; fi",
            "! printenv",
            "while true; do env; done",
            // .env reads, quoted or not
            "cat \".env\"",
            "cat 'apps/api/.env.local' | grep x",
            // found by review, each checked against bash 5.3 with a marker:
            // a `#` mid-word is not a comment (after a continuation, a
            // substitution, an escaped character)
            "echo x\\\n#;printenv",
            "echo $(date)#;printenv",
            "echo $((1))#;printenv",
            "cat <(date)#;printenv",
            "echo a\\ #;printenv",
            "echo \\;#;printenv",
            "echo 'a'#;printenv",
            // bash finds a closing backtick without regard to quotes
            "echo `echo '`\nprintenv\necho '`",
            // `>&` is a redirection, not a background `&`
            "cat >&2 .env",
            "cat 2>&1 .env",
            // in POSIX double quotes `\` escapes only `$`, backtick, `"`, `\`
            "\"C:\\Program Files\\Git\\bin\\bash.exe\" -c 'x; printenv '",
            // a command name built from escapes
            "pr\\intenv",
            // programs that run a quoted string as code
            "echo 'x; printenv ' | source /dev/stdin",
            ". <(echo 'x; printenv ')",
            "trap 'x; printenv ' EXIT",
            "git rebase --exec 'x; printenv ' HEAD~1",
            "git -c core.pager='less; printenv ' log",
            "ssh host 'x; printenv '",
            "parallel 'x; printenv ' ::: 1",
            "find . -exec $SHELL -c 'x; printenv ' \\;",
            "find . -exec \"$SHELL\" -c 'x; printenv ' \\;",
            "find . -exec $'\\x73h' -c 'x; printenv ' \\;",
            "find . -exec /bin/s? -c 'x; printenv ' \\;",
            // an evaluator spelled in ANSI-C quotes is still `sh`
            "ionice $'sh' -c 'x; printenv '",
        ] {
            assert!(bash(c).is_some(), "{c:?} was allowed");
        }
        for c in [
            "Write-Output 'x' | gci env:",
            "Write-Output \"a\"; Get-ChildItem env:",
            "Write-Output 'it''s' ; gci env:",
            "Write-Output `\"a ; gci env:",
            "Write-Output \"$(Get-ChildItem env:)\"",
            "Write-Output \"a $(gci env:) b\"",
            "(Get-ChildItem env:)",
            "& { Get-ChildItem env: }",
            "iex 'Get-ChildItem env:'",
            "Invoke-Expression \"gci env:\"",
            "@'\nGet-ChildItem env:\n'@ | iex",
            "@\"\n$(Get-ChildItem env:)\n\"@ | Out-File x.txt",
            "pwsh -Command \"Write-Output 'a'; gci env:\"",
            // a substitution's output is the outer command's argument
            "gci (Write-Output env:)",
            "gci $(Write-Output env:)",
            // a quote inside a comment is not a quote
            "Write-Output 1 # '\ngci env:\n#'",
            "<# ' #> gci env: # '",
            // after `;` a comment starts (checked against pwsh 7.6)
            "Write-Output 1;# '\ngci env:\n#'",
            // after `--%` a `#` is passed on, not a comment; `|` still pipes
            "Write-Output --% #'|gci env:",
            // a script block is checked on its own AND as an argument
            "ls { env: }",
            "$x | % { gci env: }",
            "foreach ($i in 1) { Get-ChildItem env: }",
            // `x@"` is a bareword and an ordinary string, not a here-string
            "Write-Output x@\"\nfoo\" ; gci env: ; \"\n\"@",
            // backtick + newline continues the line
            "Get-ChildItem `\n env:",
            "Write-Output 'unterminated ; gci env:",
            "Write-Output \"unterminated ; gci env:",
            "Get-Content '.env'",
            // found by review, each checked against pwsh 7.6 with a marker:
            "Get-ChildItem 2>&1 env:",
            // smart quotes are quotes to PowerShell
            "Write-Output 'a\u{2018}; gci env:; \u{2018}b'",
            "Write-Output \"a\u{201C}; gci env:; \u{201C}b\"",
            // `${...}` is a variable; a quote in its name is no quote
            "Write-Output ${a '} ; gci env: ; ${'}",
            // a here-string header may end in spaces; a lone CR ends a line
            "Write-Output @' \nit's `\n'@\ngci env:\n#'",
            "Write-Output @'\na\r'@\ngci env:\n'@ #'",
            // a `#` after an escaped space is mid-word
            "Write-Output a` #;gci env:",
        ] {
            assert!(ps(c).is_some(), "{c:?} was allowed");
        }
    }

    /// Nested wrappers are read in linear time; the first-word fallback
    /// once doubled the work per level (`nice` x20 took 9.5 s).
    #[test]
    fn nested_wrappers_are_linear() {
        let cmd = format!("{}x", "nice ".repeat(200));
        let t = std::time::Instant::now();
        assert!(bash(&cmd).is_none());
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }

    /// `with-secret run` checks its child's argv joined with spaces, which has
    /// already lost its quoting, so it keeps the quote-unaware check.
    #[test]
    fn the_argv_check_stays_quote_unaware() {
        assert!(command_dump_reason("git grep -E 'a|printenv|b'").is_some());
        assert!(command_dump_reason("cargo test").is_none());
        // `sh -c x; "printenv"` joined from argv: sh runs `printenv`
        assert!(command_dump_reason("sh -c x; \"printenv\"").is_some());
    }

    #[test]
    fn the_first_word_is_still_read_as_before() {
        // not a dump in either shell, but the pre-0.5.4 check denied it
        assert!(segment_reason("A=1\\declare").is_some());
    }

    /// The fallback splits exactly as before 0.5.4: a wider split could cut
    /// a command off from its own arguments.
    #[test]
    fn the_fallback_still_splits_the_original_way() {
        assert!(loose_reason("type ) .env").is_some());
        assert!(loose_reason("cat { x .env").is_some());
        assert!(loose_reason("gci & env:").is_some());
    }

    #[test]
    fn other_tools_and_bad_input_pass() {
        assert!(dump_reason("Write", &json!({"file_path": ".env"})).is_none());
        assert!(dump_reason("Bash", &json!({})).is_none());
    }
}
