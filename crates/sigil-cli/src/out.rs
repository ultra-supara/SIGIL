//! Writing `--out` (PR-4b-2a spec §3.1): never through an existing file, and never into a scan
//! root, whatever is renamed meanwhile.
//!
//! `fs::write` opens an existing file and truncates it. Through a hard link, that is another
//! name's content (a model blob, an input). Through a symlink swapped in after `--out` was
//! checked, it is any file. Here:
//! - when `--out` is checked, the existing part of its directory is opened from `/` one
//!   component at a time without following a symlink, and that directory's fd is kept
//!   ([`Target::pin`]). It must not be, or lie under, a scan root, by `dev:ino`;
//! - at the write, missing directories are created under the pinned fd, and the final directory
//!   is checked against the scan roots again;
//! - the document goes to a new temporary file (`O_EXCL`, mode 0600: readable by its owner only);
//! - it is exchanged with the file at the name (`RENAME_EXCHANGE`). The file actually displaced is
//!   checked, and a protected one (an input of the run) or a directory is put back.
//!
//! A directory renamed after `--out` was checked therefore cannot redirect the write: the fd is
//! the directory that was checked. What remains:
//! - a directory moved into a scan root between the last check and the exchange;
//! - a run killed after the exchange and before a put-back (see [`install`]).

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    fstat, mkdirat, openat, renameat, renameat_with, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags, RenameFlags,
};
use rustix::io::Errno;

/// The longest prefix of the output's name that a temporary name keeps. With `.` and
/// `.sigil-<pid>-<k>.tmp`, it stays under `NAME_MAX` (255).
pub const TEMP_NAME_PREFIX: usize = 200;
/// Temporary names tried before giving up; a name already taken (a stale file) is skipped.
pub const TEMP_TRIES: u32 = 100;
/// Directories walked up from an output before giving up.
const MAX_DEPTH: usize = 4096;
/// A directory, opened for its fd only (search permission is enough), never through a symlink.
const DIR: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

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

/// An output, pinned when `--out` is checked: the deepest existing directory of its path (an
/// fd), the directories after it, its name, and the scan roots it must stay out of.
pub struct Target {
    dir: OwnedFd,
    missing: Vec<OsString>,
    name: OsString,
    path: PathBuf,
    roots: Vec<(u64, u64)>,
}

impl Target {
    /// Pins `target`: an absolute path whose existing part has no symlink, as `check_out`
    /// resolved it. Refuses a directory that is, or lies under, one of `roots` (`dev:ino`), and a
    /// directory at `target` itself: it would only be exchanged and put back (review of #89).
    /// Nothing is created yet.
    pub fn pin(target: &Path, roots: Vec<(u64, u64)>) -> Result<Target, String> {
        let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
            return Err("not a file path".to_string());
        };
        let mut dir = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("/: {e}"))?;
        let mut at = PathBuf::from("/");
        let mut missing = vec![];
        for c in parent.components() {
            let part = match c {
                Component::RootDir => continue,
                Component::Normal(part) => part,
                _ => return Err(format!("{} is not a resolved path", target.display())),
            };
            at.push(part);
            if !missing.is_empty() {
                missing.push(part.to_os_string());
                continue;
            }
            match openat(&dir, part, DIR, Mode::empty()) {
                Ok(fd) => dir = fd,
                Err(Errno::NOENT) => missing.push(part.to_os_string()),
                Err(e) => return Err(changed(&at, e)),
            }
        }
        if contained(&dir, &roots)? {
            return Err(format!(
                "{} is, or lies under, a scan root",
                parent.display()
            ));
        }
        if missing.is_empty() {
            if let Ok(st) = statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
                    return Err(format!("{} is a directory", target.display()));
                }
            }
        }
        Ok(Target {
            dir,
            missing,
            name: name.to_os_string(),
            path: target.to_path_buf(),
            roots,
        })
    }

    /// The path as checked, for messages.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Adds a scan root by the `dev:ino` a read saw (PR-4d-1: the installation a service unit
    /// names, and the unit's directory), called `name` in the message. Refused, as `pin` refuses
    /// one, when the pinned directory is, or lies under, it; the write checks it again, as every
    /// root. An error of the check itself is returned as it is.
    pub fn exclude(&mut self, root: (u64, u64), name: &str) -> Result<(), String> {
        if contained(&self.dir, &[root])? {
            return Err(format!(
                "its directory is, or lies under, the {name} directory as it was read"
            ));
        }
        self.roots.push(root);
        Ok(())
    }

    /// Writes `bytes` at the pinned target. A file there whose `dev:ino` is in `protected` (an
    /// input of the run) is not replaced.
    pub fn write(&self, bytes: &[u8], protected: &[(u64, u64)]) -> Result<(), String> {
        let dir = self.final_dir()?;
        let (tmp, fd) = create_temp(&dir, &self.name)?;
        let ours = identity(&fd)?;
        let written = std::fs::File::from(fd)
            .write_all(bytes)
            .map_err(|e| e.to_string())
            .and_then(|()| install(&dir, &tmp, &self.name, protected));
        if written.is_err() {
            cleanup(&dir, &tmp, ours);
        }
        written
    }

    /// The pinned directory with the missing ones created under it. A directory is checked
    /// against the scan roots before anything is created in it, and each new one is opened
    /// without following a symlink and checked in turn (review of #88).
    fn final_dir(&self) -> Result<OwnedFd, String> {
        let mut dir = openat(&self.dir, ".", DIR, Mode::empty()).map_err(|e| e.to_string())?;
        self.outside(&dir)?;
        for part in &self.missing {
            match mkdirat(&dir, part, Mode::from_raw_mode(0o777)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(e) => return Err(format!("{}: {e}", part.to_string_lossy())),
            }
            dir =
                openat(&dir, part, DIR, Mode::empty()).map_err(|e| changed(Path::new(part), e))?;
            self.outside(&dir)?;
        }
        Ok(dir)
    }

    /// `dir` is not a scan root, and does not lie under one.
    fn outside(&self, dir: &OwnedFd) -> Result<(), String> {
        if contained(dir, &self.roots)? {
            return Err(
                "its directory is, or lies under, a scan root now; not written".to_string(),
            );
        }
        Ok(())
    }
}

/// An open file's `dev:ino`.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn identity(fd: &OwnedFd) -> Result<(u64, u64), String> {
    fstat(fd)
        .map(|st| (st.st_dev as u64, st.st_ino as u64))
        .map_err(|e| e.to_string())
}

/// Removes `tmp` only while it is still the temporary file this write created (`ours`). After a
/// failed rollback, `tmp` names the file the exchange displaced, which is left as it is (review
/// of #88).
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn cleanup(dir: &OwnedFd, tmp: &OsStr, ours: (u64, u64)) {
    if let Ok(st) = statat(dir, tmp, AtFlags::SYMLINK_NOFOLLOW) {
        if (st.st_dev as u64, st.st_ino as u64) == ours {
            // Best effort: the error being reported is the write's.
            let _ = unlinkat(dir, tmp, AtFlags::empty());
        }
    }
}

/// Whether `dir` is one of `roots` or lies under one, by `dev:ino`: `..` is walked up to `/`.
fn contained(dir: &OwnedFd, roots: &[(u64, u64)]) -> Result<bool, String> {
    if roots.is_empty() {
        return Ok(false);
    }
    let id = identity;
    let mut here = openat(dir, ".", DIR, Mode::empty()).map_err(|e| e.to_string())?;
    for _ in 0..MAX_DEPTH {
        let at = id(&here)?;
        if roots.contains(&at) {
            return Ok(true);
        }
        let up = openat(&here, "..", DIR, Mode::empty()).map_err(|e| e.to_string())?;
        if id(&up)? == at {
            return Ok(false);
        }
        here = up;
    }
    Err(format!("deeper than {MAX_DEPTH} directories"))
}

/// A new temporary file in `dir`, mode 0600. `O_EXCL` never opens an existing one, and a name
/// already taken is skipped.
fn create_temp(dir: &OwnedFd, name: &OsStr) -> Result<(OsString, OwnedFd), String> {
    for attempt in 0..TEMP_TRIES {
        let tmp = temp_name(name, attempt);
        match openat(
            dir,
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => return Ok((tmp, fd)),
            Err(Errno::EXIST) => continue,
            Err(e) => return Err(format!("the temporary file {}: {e}", tmp.to_string_lossy())),
        }
    }
    Err(format!("no free temporary name after {TEMP_TRIES} tries"))
}

/// Puts the temporary file `tmp` at `name`.
/// - An existing file there is exchanged with it (`RENAME_EXCHANGE`), so the file actually
///   displaced is what is checked: a protected one (an input of the run) or a directory is put
///   back, and anything else is unlinked.
/// - With nothing at `name`, `RENAME_NOREPLACE` keeps it so; a file that appears meanwhile is
///   exchanged on the next try.
/// - A file system without the exchange: [`without_exchange`].
///
/// The put-back is a second system call: a run killed after the exchange and before it leaves
/// the displaced file at `tmp`, whole, and the document at `name` (review of #89;
/// docs/architecture-and-safety.md). A displaced file that cannot be checked is put back.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn install(
    dir: &OwnedFd,
    tmp: &OsStr,
    name: &OsStr,
    protected: &[(u64, u64)],
) -> Result<(), String> {
    for _ in 0..3 {
        match renameat_with(dir, tmp, dir, name, RenameFlags::EXCHANGE) {
            Ok(()) => {
                // `tmp` now names the file that was at `name`.
                let refused = match statat(dir, tmp, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(e) => Some(format!(
                        "the file it displaced could not be checked ({e}); not replaced"
                    )),
                    Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Directory => {
                        Some("it is a directory; not replaced".to_string())
                    }
                    Ok(st) if protected.contains(&(st.st_dev as u64, st.st_ino as u64)) => {
                        Some("it is an input of this run; not replaced".to_string())
                    }
                    Ok(_) => None,
                };
                if let Some(what) = refused {
                    // Put it back; the caller then removes the document, which is at `tmp`.
                    if let Err(e) = renameat_with(dir, tmp, dir, name, RenameFlags::EXCHANGE) {
                        return Err(format!(
                            "{what}, and putting it back failed ({e}): it is named {} now",
                            tmp.to_string_lossy()
                        ));
                    }
                    return Err(what);
                }
                return unlinkat(dir, tmp, AtFlags::empty()).map_err(|e| {
                    format!(
                        "written, but the file it replaced could not be removed ({e}): it is \
                         named {} now",
                        tmp.to_string_lossy()
                    )
                });
            }
            Err(Errno::NOENT) => match renameat_with(dir, tmp, dir, name, RenameFlags::NOREPLACE) {
                Err(Errno::EXIST) => continue,
                other => return other.map_err(|e| e.to_string()),
            },
            Err(Errno::INVAL | Errno::NOSYS | Errno::OPNOTSUPP) => {
                return without_exchange(dir, tmp, name, protected)
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("the name kept changing during the write".to_string())
}

/// A file system without `RENAME_EXCHANGE`. With nothing protected, a plain rename. With
/// protected inodes, the file a rename would replace cannot be checked as it is replaced, so only
/// a name that does not exist is written (`RENAME_NOREPLACE`), and an existing file is refused:
/// fail-closed (review of #88).
fn without_exchange(
    dir: &OwnedFd,
    tmp: &OsStr,
    name: &OsStr,
    protected: &[(u64, u64)],
) -> Result<(), String> {
    if protected.is_empty() {
        return renameat(dir, tmp, dir, name).map_err(|e| e.to_string());
    }
    match renameat_with(dir, tmp, dir, name, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(Errno::EXIST) => Err(
            "this file system cannot exchange files, so an existing output is not replaced \
             while inputs are protected; remove it first"
                .to_string(),
        ),
        Err(e) => Err(format!("this file system cannot exchange files: {e}")),
    }
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
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::{temp_name, Target};

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

    /// Pinned and written at once, with no scan root.
    fn write(target: &Path, bytes: &[u8], protected: &[(u64, u64)]) -> Result<(), String> {
        Target::pin(target, vec![])?.write(bytes, protected)
    }

    #[test]
    fn a_new_file_in_new_directories_and_no_temporary_file_left() {
        let (_d, p) = dir();
        let target = p.join("a/b/out.json");
        write(&target, b"doc", &[]).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"doc");
        assert_eq!(names(&p.join("a/b")), ["out.json"]);
    }

    /// Review of #88 (P1): the temporary file is created 0600, so an existing private output does
    /// not become readable by others, and a new one is private too.
    #[test]
    fn outputs_are_readable_by_their_owner_only() {
        let (_d, p) = dir();
        let fresh = p.join("new.json");
        write(&fresh, b"doc", &[]).unwrap();
        assert_eq!(fs::metadata(&fresh).unwrap().mode() & 0o077, 0);
        let private = p.join("private.json");
        fs::write(&private, b"old").unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
        write(&private, b"doc", &[]).unwrap();
        assert_eq!(fs::metadata(&private).unwrap().mode() & 0o077, 0);
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
        assert_eq!(names(&p), ["input.bin", "out.json"]);
    }

    #[test]
    fn a_symlink_swapped_in_at_the_target_is_replaced_and_its_target_untouched() {
        let (_d, p) = dir();
        let input = p.join("input.bin");
        fs::write(&input, b"input bytes").unwrap();
        let target = p.join("out.json");
        let pinned = Target::pin(&target, vec![]).unwrap();
        // Pinned as a plain name; a symlink appears there afterwards.
        symlink(&input, &target).unwrap();
        pinned.write(b"doc", &[]).unwrap();
        assert_eq!(fs::read(&input).unwrap(), b"input bytes");
        assert!(fs::symlink_metadata(&target).unwrap().is_file());
    }

    #[test]
    fn a_symlink_on_the_way_is_refused_when_pinned() {
        let (_d, p) = dir();
        let victim = p.join("victim");
        fs::create_dir(&victim).unwrap();
        symlink(&victim, p.join("d")).unwrap();
        assert!(Target::pin(&p.join("d/out.json"), vec![]).is_err());
        assert!(Target::pin(&p.join("d/new/out.json"), vec![]).is_err());
        assert!(names(&victim).is_empty());
    }

    #[test]
    fn a_missing_directory_replaced_by_a_symlink_is_not_followed() {
        let (_d, p) = dir();
        let victim = p.join("victim");
        fs::create_dir(&victim).unwrap();
        let pinned = Target::pin(&p.join("new/out.json"), vec![]).unwrap();
        // `new` did not exist when pinned; a symlink takes its place before the write.
        symlink(&victim, p.join("new")).unwrap();
        assert!(pinned.write(b"doc", &[]).is_err());
        assert!(
            names(&victim).is_empty(),
            "nothing created through the link"
        );
    }

    /// Review of #88 (P1): the output directory and a scan root swapped by renames after the
    /// check. The write goes to the pinned directory, and the scan root keeps its content.
    #[test]
    fn a_directory_renamed_after_the_check_does_not_redirect_the_write() {
        let (_d, p) = dir();
        fs::create_dir_all(p.join("models/blobs")).unwrap();
        fs::write(p.join("models/blobs/sha256-abc"), b"blob").unwrap();
        fs::create_dir(p.join("reports")).unwrap();
        let roots = vec![inode(&p.join("models"))];
        let pinned = Target::pin(&p.join("reports/blobs/sha256-abc"), roots).unwrap();
        fs::rename(p.join("reports"), p.join("reports.old")).unwrap();
        fs::rename(p.join("models"), p.join("reports")).unwrap();
        pinned.write(b"doc", &[]).unwrap();
        assert_eq!(
            fs::read(p.join("reports/blobs/sha256-abc")).unwrap(),
            b"blob"
        );
        assert_eq!(
            fs::read(p.join("reports.old/blobs/sha256-abc")).unwrap(),
            b"doc"
        );
    }

    #[test]
    fn a_directory_moved_under_a_scan_root_after_the_check_is_refused() {
        let (_d, p) = dir();
        fs::create_dir(p.join("models")).unwrap();
        fs::create_dir(p.join("reports")).unwrap();
        let roots = vec![inode(&p.join("models"))];
        let pinned = Target::pin(&p.join("reports/out.json"), roots).unwrap();
        fs::rename(p.join("reports"), p.join("models/reports")).unwrap();
        assert!(pinned.write(b"doc", &[]).is_err());
        assert!(names(&p.join("models/reports")).is_empty());
    }

    #[test]
    fn an_excluded_root_renamed_then_entered_by_the_pinned_directory_is_refused() {
        let (_d, p) = dir();
        fs::create_dir(p.join("install")).unwrap();
        fs::create_dir(p.join("reports")).unwrap();
        let mut pinned = Target::pin(&p.join("reports/out.json"), vec![]).unwrap();
        pinned
            .exclude(inode(&p.join("install")), "install")
            .unwrap();
        fs::rename(p.join("install"), p.join("moved")).unwrap();
        fs::rename(p.join("reports"), p.join("moved/reports")).unwrap();
        assert!(pinned.write(b"doc", &[]).is_err());
        assert!(names(&p.join("moved/reports")).is_empty());
        // Excluding a root the pinned directory already lies under is refused at once.
        let mut pinned = Target::pin(&p.join("moved/reports/out.json"), vec![]).unwrap();
        let e = pinned
            .exclude(inode(&p.join("moved")), "install")
            .unwrap_err();
        assert_eq!(
            e,
            "its directory is, or lies under, the install directory as it was read"
        );
    }

    /// Review of #88 (P1): the pinned directory moved into a scan root before the write, with a
    /// directory still to create. Nothing is created in the scan root.
    #[test]
    fn a_directory_moved_under_a_scan_root_gets_no_new_directory() {
        let (_d, p) = dir();
        fs::create_dir(p.join("models")).unwrap();
        fs::create_dir(p.join("reports")).unwrap();
        let roots = vec![inode(&p.join("models"))];
        let pinned = Target::pin(&p.join("reports/new/out.json"), roots).unwrap();
        fs::rename(p.join("reports"), p.join("models/reports")).unwrap();
        assert!(pinned.write(b"doc", &[]).is_err());
        assert!(!p.join("models/reports/new").exists());
    }

    fn open_dir(p: &Path) -> std::os::fd::OwnedFd {
        rustix::fs::open(
            p,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    /// Review of #88 (P2): without `RENAME_EXCHANGE`, protected inputs make the write fail-closed:
    /// a new name is written, an existing file is not replaced.
    #[test]
    fn without_the_exchange_protected_inputs_mean_no_replacement() {
        let (_d, p) = dir();
        let d = open_dir(&p);
        let stage = |name: &str| {
            fs::write(p.join(name), b"doc").unwrap();
            std::ffi::OsString::from(name)
        };
        let some = [(1u64, 1u64)];
        // An existing output, inputs protected: refused, both files as they were.
        fs::write(p.join("out.json"), b"old").unwrap();
        let tmp = stage("t1");
        assert!(super::without_exchange(&d, &tmp, "out.json".as_ref(), &some).is_err());
        assert_eq!(fs::read(p.join("out.json")).unwrap(), b"old");
        assert!(p.join("t1").exists());
        // A new name, inputs protected: written.
        let tmp = stage("t2");
        super::without_exchange(&d, &tmp, "new.json".as_ref(), &some).unwrap();
        assert_eq!(fs::read(p.join("new.json")).unwrap(), b"doc");
        // Nothing protected: a plain rename replaces.
        let tmp = stage("t3");
        super::without_exchange(&d, &tmp, "out.json".as_ref(), &[]).unwrap();
        assert_eq!(fs::read(p.join("out.json")).unwrap(), b"doc");
    }

    /// Review of #88 (P2): after a failed rollback, the temporary name holds the displaced file,
    /// and the cleanup leaves it: only this write's own file is removed.
    #[test]
    fn the_cleanup_removes_only_this_write_s_file() {
        let (_d, p) = dir();
        let d = open_dir(&p);
        fs::write(p.join("tmp"), b"displaced input").unwrap();
        super::cleanup(&d, "tmp".as_ref(), (0, 0));
        assert_eq!(fs::read(p.join("tmp")).unwrap(), b"displaced input");
        super::cleanup(&d, "tmp".as_ref(), inode(&p.join("tmp")));
        assert!(!p.join("tmp").exists());
    }

    #[test]
    fn a_scan_root_or_a_directory_under_it_is_refused_when_pinned() {
        let (_d, p) = dir();
        fs::create_dir_all(p.join("models/sub")).unwrap();
        let roots = vec![inode(&p.join("models"))];
        assert!(Target::pin(&p.join("models/out.json"), roots.clone()).is_err());
        assert!(Target::pin(&p.join("models/sub/new/out.json"), roots.clone()).is_err());
        assert!(Target::pin(&p.join("elsewhere/out.json"), roots).is_ok());
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

    /// The input whose inode is protected is what the exchange displaced: it is put back.
    #[test]
    fn a_protected_inode_is_not_replaced() {
        let (_d, p) = dir();
        let input = p.join("input.bin");
        fs::write(&input, b"input bytes").unwrap();
        let target = p.join("out.json");
        fs::hard_link(&input, &target).unwrap();
        assert!(write(&target, b"doc", &[inode(&input)]).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"input bytes");
        assert_eq!(inode(&target), inode(&input));
        assert_eq!(
            names(&p),
            ["input.bin", "out.json"],
            "no temporary file left"
        );
    }

    /// A directory put at `--out` after it was pinned: exchanged, then put back.
    #[test]
    fn a_directory_at_out_is_put_back_and_the_temporary_file_removed() {
        let (_d, p) = dir();
        let target = Target::pin(&p.join("out.json"), vec![]).unwrap();
        fs::create_dir_all(p.join("out.json/x")).unwrap();
        let e = target.write(b"doc", &[]).unwrap_err();
        assert!(e.contains("it is a directory; not replaced"), "{e}");
        assert_eq!(names(&p), ["out.json"]);
        assert_eq!(names(&p.join("out.json")), ["x"]);
    }

    /// Review of #89: a directory at `--out` when it is pinned is refused then: nothing is
    /// exchanged, so no crash can leave it at a temporary name.
    #[test]
    fn a_directory_at_out_is_refused_when_pinned() {
        let (_d, p) = dir();
        fs::create_dir_all(p.join("out.json/x")).unwrap();
        let e = write(&p.join("out.json"), b"doc", &[]).unwrap_err();
        assert!(e.ends_with("out.json is a directory"), "{e}");
        assert_eq!(names(&p), ["out.json"]);
        assert_eq!(names(&p.join("out.json")), ["x"]);
    }
}
