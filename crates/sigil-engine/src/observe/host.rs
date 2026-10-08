//! The run's own facts (plan §4.2 "Recorded"): who ran SIGIL and on what kernel, and, in observe
//! mode, the boot it observed.
//!
//! The user, group, capabilities, and kernel come from system calls (`getuid`, `getgid`, `capget`,
//! `uname`), not from files. The boot ID identifies the boot that observed processes belong to,
//! so it is read only in observe mode, from `<proc root>/sys/kernel/random/boot_id` (on the C-6
//! allowlist).

use std::os::fd::AsFd;
use std::path::Path;

use rustix::fs::{Mode as FileMode, OFlags};
use sigil_model::{Mode, ObservationMeta, Timestamp};

/// The run's `ObservationMeta`, with `finished_at` = `started_at` until the caller sets it.
/// SIGIL's namespaces are left unset; the observe-mode assembler records the one it reads.
pub fn meta(mode: Mode, proc_root: &Path, started_at: Timestamp) -> ObservationMeta {
    ObservationMeta {
        finished_at: started_at.clone(),
        started_at,
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        capabilities: capabilities(),
        boot_id: match mode {
            Mode::Observe => boot_id(proc_root).unwrap_or_default(),
            Mode::Static => String::new(),
        },
        kernel: rustix::system::uname()
            .release()
            .to_string_lossy()
            .into_owned(),
        net_ns: None,
        mnt_ns: None,
    }
}

/// The effective capabilities, as `CAP_*` names in bit order. If they cannot be read, the one
/// entry says so: unknown is not none.
fn capabilities() -> Vec<String> {
    match rustix::thread::capabilities(None) {
        Ok(sets) => sets
            .effective
            .iter_names()
            .map(|(name, _)| format!("CAP_{name}"))
            .collect(),
        Err(e) => vec![format!("unknown (capget: {e})")],
    }
}

/// The boot ID in its UUID form (lowercase hex, `8-4-4-4-12`), or `None`. `None` is recorded as
/// an empty boot ID, which leaves the checks that rest on a process's identity open
/// (`analyze::exposure`).
fn boot_id(proc_root: &Path) -> Option<String> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let root = rustix::fs::openat(rustix::fs::CWD, proc_root, flags, FileMode::empty()).ok()?;
    let file = rustix::fs::openat(
        root.as_fd(),
        "sys/kernel/random/boot_id",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        FileMode::empty(),
    )
    .ok()?;
    // 36 characters and a newline; one more byte shows a longer file.
    let mut buffer = [0u8; 38];
    let mut len = 0;
    while len < buffer.len() {
        match rustix::io::read(&file, &mut buffer[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return None,
        }
    }
    let text = std::str::from_utf8(&buffer[..len]).ok()?;
    let id = text.strip_suffix('\n').unwrap_or(text);
    is_uuid(id).then(|| id.to_string())
}

fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}
