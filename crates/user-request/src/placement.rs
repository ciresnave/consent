// SPDX-License-Identifier: MIT OR Apache-2.0
//! The write-time check for a `SecretPlacement` approval (PM condition (c),
//! 2026-11-24). The approval is bound to the path NAMED in the subject; this
//! re-reads the disk at the moment of the write and refuses anything that is
//! no longer exactly that file.
//!
//! The target must be a plain file at exactly the approved path (no symlink,
//! junction or other reparse point), its parent resolving to the same place.
//! An EXISTING target must also be owner-only: on Windows its DACL may name
//! only the owner, SYSTEM and Administrators; on Unix it must not be group-
//! or world-accessible, and the parent must not be group- or world-writable.
//! ⚠️ A target that does not exist yet has no ACL to read: the writer must
//! create it owner-only, and on Windows nothing here checks the parent.

use std::path::{Path, PathBuf};

use crate::request::parse_secret_placement_subject;

/// Strips the Windows verbatim prefix `canonicalize` adds.
fn plain(p: &Path) -> String {
    let s = p.to_string_lossy().into_owned();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

/// Re-checks, at the moment of the write, that `subject` (a `SecretPlacement`
/// subject) still names a plain file at exactly its approved path. Returns
/// the path to write. Any doubt is an `Err`: the caller must not write.
///
/// The comparison is EXACT: the canonical parent plus the file name must
/// spell the approved path character for character, so a symlinked or
/// junctioned directory, a `..`, or a different case all fail closed.
pub fn verify_placement_target(subject: &str) -> Result<PathBuf, String> {
    let (_, path) = parse_secret_placement_subject(subject)
        .ok_or_else(|| "not a placement subject".to_string())?;
    let target = Path::new(path);
    let parent = target.parent().ok_or("the path has no parent")?;
    let file = target.file_name().ok_or("the path names no file")?;
    let canon_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("parent of {path} does not resolve: {e}"))?;
    let resolved = plain(&canon_parent.join(file));
    if resolved != path {
        return Err(format!(
            "{path} resolves to {resolved}: a link, a case difference or a changed directory"
        ));
    }
    match std::fs::symlink_metadata(target) {
        Ok(m) => {
            if m.file_type().is_symlink() || !m.is_file() {
                return Err(format!("{path} is not a plain file"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                // FILE_ATTRIBUTE_REPARSE_POINT: a junction or a placeholder
                if m.file_attributes() & 0x400 != 0 {
                    return Err(format!("{path} is a reparse point"));
                }
                crate::placement_acl::require_owner_only(target)
                    .map_err(|e| format!("{path} is not owner-only: {e}"))?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if m.permissions().mode() & 0o077 != 0 {
                    return Err(format!("{path} is accessible to group or others"));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{path}: {e}")),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let pm = std::fs::metadata(&canon_parent).map_err(|e| e.to_string())?;
        if pm.permissions().mode() & 0o022 != 0 {
            return Err(format!("the directory of {path} is writable by others"));
        }
    }
    Ok(target.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::secret_placement_subject;
    use tempfile::tempdir;

    fn subject_for(p: &Path) -> String {
        secret_placement_subject("TOKEN", &plain(&std::fs::canonicalize(p).unwrap())).unwrap()
    }

    #[test]
    fn a_new_file_in_a_real_directory_passes() {
        let d = tempdir().unwrap();
        let dir = std::fs::canonicalize(d.path()).unwrap();
        let s = secret_placement_subject("TOKEN", &plain(&dir.join("new.env"))).unwrap();
        assert!(verify_placement_target(&s).is_ok(), "{s}");
    }

    #[test]
    fn an_existing_plain_file_passes_and_a_directory_does_not() {
        let d = tempdir().unwrap();
        let f = d.path().join("a.env");
        std::fs::write(&f, "x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        crate::placement_acl::lock_to_current_user(&f);
        assert!(verify_placement_target(&subject_for(&f)).is_ok());
        let sub = d.path().join("dir");
        std::fs::create_dir(&sub).unwrap();
        assert!(verify_placement_target(&subject_for(&sub)).is_err());
    }

    /// An existing target whose ACL grants Everyone is refused at the write.
    #[cfg(windows)]
    #[test]
    fn an_existing_target_granted_to_everyone_is_refused() {
        let d = tempdir().unwrap();
        let f = d.path().join("a.env");
        std::fs::write(&f, "x").unwrap();
        crate::placement_acl::lock_to_current_user(&f);
        assert!(verify_placement_target(&subject_for(&f)).is_ok());
        let st = std::process::Command::new("icacls")
            .arg(&f)
            .args(["/grant", "*S-1-1-0:R"])
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
        let e = verify_placement_target(&subject_for(&f)).unwrap_err();
        assert!(e.contains("not owner-only"), "{e}");
    }

    /// A parent that is swapped for a link after approval no longer spells
    /// the approved path.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_target_or_parent_is_refused() {
        let d = tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let victim = real.join("victim");
        std::fs::write(&victim, "x").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let s = secret_placement_subject(
            "T",
            &plain(&std::fs::canonicalize(d.path()).unwrap().join("link")),
        )
        .unwrap();
        assert!(verify_placement_target(&s).is_err(), "a symlink target");
        let dl = d.path().join("dirlink");
        std::os::unix::fs::symlink(&real, &dl).unwrap();
        let s = secret_placement_subject(
            "T",
            &plain(
                &std::fs::canonicalize(d.path())
                    .unwrap()
                    .join("dirlink")
                    .join("victim"),
            ),
        )
        .unwrap();
        assert!(verify_placement_target(&s).is_err(), "a symlinked parent");
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_target_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let f = d.path().join("a.env");
        std::fs::write(&f, "x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify_placement_target(&subject_for(&f)).is_err());
    }

    #[test]
    fn a_missing_parent_is_refused() {
        let d = tempdir().unwrap();
        let base = plain(&std::fs::canonicalize(d.path()).unwrap());
        let sep = std::path::MAIN_SEPARATOR;
        let s = secret_placement_subject("T", &format!("{base}{sep}nope{sep}f")).unwrap();
        assert!(verify_placement_target(&s).is_err());
    }

    /// A different case of the same directory is not the approved path
    /// (control: the exact spelling passes, in the first test).
    #[cfg(windows)]
    #[test]
    fn a_different_case_spelling_is_refused() {
        let d = tempdir().unwrap();
        let f = std::fs::canonicalize(d.path()).unwrap().join("a.env");
        let p = plain(&f);
        let swapped: String = p
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        // keep the drive and separators valid
        let s = secret_placement_subject("T", &swapped).unwrap();
        assert!(verify_placement_target(&s).is_err());
    }

    /// A junction swapped in for the approved directory (Windows reparse).
    #[cfg(windows)]
    #[test]
    fn a_junctioned_parent_is_refused() {
        let d = tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let junction = base.join("jct");
        let st = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&real)
            .output()
            .unwrap();
        assert!(st.status.success(), "mklink: {st:?}");
        let s = secret_placement_subject("T", &plain(&junction.join("f.env"))).unwrap();
        assert!(verify_placement_target(&s).is_err());
    }
}
