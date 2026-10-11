//! Writing `--out` (PR-4b-2a spec §3.1): never through an existing file.
//!
//! `fs::write` opens an existing file and truncates it. Through a hard link, that is another
//! name's content (a model blob, an input). Through a symlink swapped in after `--out` was
//! checked, it is any file. Here:
//! - the checked path's directory is opened from `/` one component at a time, without following
//!   a symlink;
//! - the document goes to a new temporary file (`O_EXCL`);
//! - a protected inode at the name is refused;
//! - a rename replaces the name.
//!
//! An existing file at that name is replaced, never opened, and is never left half-written.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{mkdirat, openat, renameat, statat, unlinkat, AtFlags, Mode, OFlags};
use rustix::io::Errno;

/// The longest prefix of the output's name that a temporary name keeps. With `.` and
/// `.sigil-<pid>-<k>.tmp`, it stays under `NAME_MAX` (255).
pub const TEMP_NAME_PREFIX: usize = 200;
/// Temporary names tried before giving up; a name already taken (a stale file) is skipped.
const TEMP_TRIES: u32 = 100;

/// The `attempt`-th temporary sibling this process writes `name` through:
/// `.<name, at most 200 bytes>.sigil-<pid>-<attempt>.tmp`.
pub fn temp_name(name: &OsStr, attempt: u32) -> OsString {
    let bytes = name.as_bytes();
    let mut tmp = OsString::from(".");
    tmp.push(OsStr::from_bytes(
        &bytes[..bytes.len().min(TEMP_NAME_PREFIX)],
    ));
    tmp.push(format!(".sigil-{}-{attempt}.tmp", std::process::id()));
    tmp
}

/// Writes `bytes` to `target`: an absolute path whose existing part has no symlink, as
/// `check_out` resolved it. Missing directories are created on their open parents. A file at
/// `target` whose `dev:ino` is in `protected` (an input of the run) is not replaced.
pub fn write(target: &Path, bytes: &[u8], protected: &[(u64, u64)]) -> Result<(), String> {
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return Err("not a file path".to_string());
    };
    let dir = open_dir(parent)?;
    let (tmp, fd) = create_temp(&dir, name)?;
    let written = std::fs::File::from(fd)
        .write_all(bytes)
        .map_err(|e| e.to_string())
        .and_then(|()| not_protected(&dir, name, protected))
        .and_then(|()| renameat(&dir, &tmp, &dir, name).map_err(|e| e.to_string()));
    if written.is_err() {
        // Best effort: the error being reported is the write's.
        let _ = unlinkat(&dir, &tmp, AtFlags::empty());
    }
    written
}

/// A new temporary file in `dir`. `O_EXCL` never opens an existing one, and a name already taken
/// is skipped.
fn create_temp(dir: &OwnedFd, name: &OsStr) -> Result<(OsString, OwnedFd), String> {
    for attempt in 0..TEMP_TRIES {
        let tmp = temp_name(name, attempt);
        match openat(
            dir,
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o666),
        ) {
            Ok(fd) => return Ok((tmp, fd)),
            Err(Errno::EXIST) => continue,
            Err(e) => return Err(format!("the temporary file {}: {e}", tmp.to_string_lossy())),
        }
    }
    Err(format!("no free temporary name after {TEMP_TRIES} tries"))
}

/// Refuses a file at `name` whose `dev:ino` is protected, as the name is just before the rename.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn not_protected(dir: &OwnedFd, name: &OsStr, protected: &[(u64, u64)]) -> Result<(), String> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if protected.contains(&(st.st_dev as u64, st.st_ino as u64)) => {
            Err("it is an input of this run; not replaced".to_string())
        }
        Ok(_) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// `path`, opened from `/` one component at a time. `O_PATH` needs only search permission, and
/// `O_NOFOLLOW | O_DIRECTORY` refuses a symlink, so one swapped into the path after it was
/// checked is never followed. A missing component is created on its open parent, never through
/// a link.
fn open_dir(path: &Path) -> Result<OwnedFd, String> {
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("/: {e}"))?;
    let mut at = PathBuf::from("/");
    for c in path.components() {
        let name = match c {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => return Err(format!("{} is not a resolved path", path.display())),
        };
        at.push(name);
        dir = match openat(&dir, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                match mkdirat(&dir, name, Mode::from_raw_mode(0o777)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => return Err(format!("{}: {e}", at.display())),
                }
                openat(&dir, name, flags, Mode::empty()).map_err(|e| changed(&at, e))?
            }
            Err(e) => return Err(changed(&at, e)),
        };
    }
    Ok(dir)
}

fn changed(at: &Path, e: Errno) -> String {
    match e {
        Errno::LOOP | Errno::NOTDIR => format!(
            "{} changed after it was checked: it is a symlink or not a directory now",
            at.display()
        ),
        e => format!("{}: {e}", at.display()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::path::{Path, PathBuf};

    use super::{temp_name, write};

    /// A temporary directory by its canonical path, as `check_out` gives targets.
    fn dir() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::TempDir::new().unwrap();
        let p = fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn inode(p: &Path) -> (u64, u64) {
        let m = fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    }

    #[test]
    fn a_new_file_in_new_directories_and_no_temporary_file_left() {
        let (_d, p) = dir();
        let target = p.join("a/b/out.json");
        write(&target, b"doc", &[]).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"doc");
        assert_eq!(names(&p.join("a/b")), ["out.json"]);
    }

    #[test]
    fn a_hard_link_at_out_is_replaced_not_written_through() {
        let (_d, p) = dir();
        let input = p.join("input.bin");
        fs::write(&input, b"input bytes").unwrap();
        let target = p.join("out.json");
        fs::hard_link(&input, &target).unwrap();
        write(&target, b"doc", &[]).unwrap();
        assert_eq!(fs::read(&input).unwrap(), b"input bytes");
        assert_eq!(fs::read(&target).unwrap(), b"doc");
        assert_ne!(inode(&input), inode(&target));
    }

    #[test]
    fn a_symlink_swapped_in_at_the_target_is_replaced_and_its_target_untouched() {
        // check_out resolved `out.json` as a plain name; a symlink appears there afterwards.
        let (_d, p) = dir();
        let input = p.join("input.bin");
        fs::write(&input, b"input bytes").unwrap();
        let target = p.join("out.json");
        symlink(&input, &target).unwrap();
        write(&target, b"doc", &[]).unwrap();
        assert_eq!(fs::read(&input).unwrap(), b"input bytes");
        assert!(fs::symlink_metadata(&target).unwrap().is_file());
    }

    #[test]
    fn a_directory_swapped_for_a_symlink_is_not_followed() {
        let (_d, p) = dir();
        let victim = p.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("out.json"), b"input bytes").unwrap();
        // Checked as a directory; a symlink to `victim` by the time of the write.
        symlink(&victim, p.join("d")).unwrap();
        assert!(write(&p.join("d/out.json"), b"doc", &[]).is_err());
        assert!(write(&p.join("d/new/out.json"), b"doc", &[]).is_err());
        assert_eq!(fs::read(victim.join("out.json")).unwrap(), b"input bytes");
        assert_eq!(
            names(&victim),
            ["out.json"],
            "nothing created through the link"
        );
    }

    #[test]
    fn a_taken_temporary_name_is_skipped_and_never_opened() {
        let (_d, p) = dir();
        let input = p.join("input.bin");
        fs::write(&input, b"input bytes").unwrap();
        // A hard link of the input planted at this process's first temporary name.
        let planted = p.join(temp_name("out.json".as_ref(), 0));
        fs::hard_link(&input, &planted).unwrap();
        write(&p.join("out.json"), b"doc", &[]).unwrap();
        assert_eq!(fs::read(&input).unwrap(), b"input bytes");
        assert_eq!(fs::read(&planted).unwrap(), b"input bytes");
        assert_eq!(fs::read(p.join("out.json")).unwrap(), b"doc");
        assert_eq!(
            names(&p).len(),
            3,
            "input, planted, out.json: {:?}",
            names(&p)
        );
    }

    #[test]
    fn a_255_byte_name_still_gets_a_temporary_name() {
        let (_d, p) = dir();
        let name = format!("{}.json", "a".repeat(250));
        write(&p.join(&name), b"doc", &[]).unwrap();
        assert_eq!(fs::read(p.join(&name)).unwrap(), b"doc");
    }

    #[test]
    fn a_protected_inode_is_not_replaced() {
        let (_d, p) = dir();
        let input = p.join("input.bin");
        fs::write(&input, b"input bytes").unwrap();
        let target = p.join("out.json");
        fs::hard_link(&input, &target).unwrap();
        assert!(write(&target, b"doc", &[inode(&input)]).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"input bytes");
        assert_eq!(
            names(&p),
            ["input.bin", "out.json"],
            "no temporary file left"
        );
    }

    #[test]
    fn a_failed_rename_removes_the_temporary_file() {
        let (_d, p) = dir();
        // A non-empty directory at `--out`: the rename fails.
        fs::create_dir_all(p.join("out.json/x")).unwrap();
        assert!(write(&p.join("out.json"), b"doc", &[]).is_err());
        assert_eq!(names(&p), ["out.json"]);
    }
}
