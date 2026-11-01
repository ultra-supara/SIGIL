//! The process table and the TCP listener tables under a proc root (plan §4.6.8).
//!
//! [`observe`] records facts only:
//! - the runtime processes and their listeners;
//! - the listeners of fronting processes, as hints;
//! - the listeners whose owner is unknown.
//!
//! What was not seen is never taken as absent:
//! - **The tables.** `net/tcp{,6}` are SIGIL's own network namespace (`self/ns/net`). A row that
//!   cannot be read is a gap.
//! - **Ownership.** A socket is attributed to a process only through that process's fd table
//!   (`fd/<n>` → `socket:[inode]`), never by its port (I-08). A listener no table holds is
//!   `Unheld` only when every process was listed, PID 1 among them, and every fd table was listed
//!   completely; otherwise its owner is `Unknown`.
//! - **The runtime.** `ollama serve`: `argv[0]`'s basename is `ollama` and `argv[1]` is `serve`.
//!   When `exe` can be read, its basename must also be `ollama`. `cmdline` is read only for
//!   processes whose `comm` is `ollama`, and only once: the argv recorded for the runtime is the
//!   one its role rests on. A process whose name or arguments cannot be read may be
//!   the runtime: it is a gap, and the listeners it holds are kept. So is the runtime when it
//!   cannot be recorded (its `stat`); the listeners it holds are kept with an `Unknown` owner.
//!
//! Processes are read one at a time, and each one's directory is closed before the next, so the
//! number of open files does not grow with the process table.
//!
//! **The runtime's descendants (PR-4d-2).** Every listed process's `stat` gives its parent; the
//! runtimes and every process descended from one are read a second time, after checking that
//! the PID is still the process listed (its start time): the executable's `dev:ino` (`stat`
//! through `exe`, which follows the link to the file the process runs and never opens it),
//! `maps` up to `proc_maps_bytes`, and `ns/mnt`. A mapping is an observation only: nothing is
//! derived from one, or from its absence (F-T1). Linking them to scanned files is
//! `analyze::runtime_processes`.
//!
//! Every entry read is in the C-6 allowlist: `net/tcp{,6}`, the proc root's directory,
//! `self/ns/{net,mnt}`, and, per process, `comm`, `cmdline`, `stat`, `exe` (`readlinkat`, and
//! `stat` through it), `maps`, `ns/net`, `ns/mnt`, `fd`, and `fd/<n>`. No link but `exe` is
//! followed, and nothing it leads to is opened.

pub mod parse;

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use sigil_model::{
    Basis, Listener, ListenerId, ListenerOwner, MappingObs, NotObservable, NsInode, ObsSource,
    Observability, ProcessExe, ProcessObs, ProcessRef, ProcessRole, Protocol, Timestamp, Tri,
    UnknownReason, UntrustedText,
};

/// The role of the runtime's server process.
pub const RUNTIME_ROLE: &str = "ollama serve";
/// Process names (`comm`) of fronting processes: their listeners are kept as hints, and never
/// lower a bind class (§4.6.8).
pub const FRONTING: &[&str] = &[
    "nginx",
    "caddy",
    "traefik",
    "haproxy",
    "envoy",
    "docker-proxy",
];

/// Bounds on what is read (C-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcBudgets {
    /// Processes listed.
    pub max_processes: u64,
    /// File descriptors listed per process.
    pub max_fds: u64,
    /// Bytes of each TCP table.
    pub max_table_bytes: u64,
    /// Bytes of each process's `maps` (PR-4d-2).
    pub max_maps_bytes: u64,
}

impl Default for ProcBudgets {
    fn default() -> Self {
        ProcBudgets {
            max_processes: 32_768,
            max_fds: 65_536,
            max_table_bytes: 16 << 20,
            max_maps_bytes: 16 << 20,
        }
    }
}

/// What was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcFacts {
    /// The runtime processes, and the processes that hold a recorded listener, by PID.
    pub processes: Vec<ProcessObs>,
    /// By ID.
    pub listeners: Vec<Listener>,
    /// SIGIL's own network namespace.
    pub own_net_ns: Option<u64>,
    /// Whether the process list was read to its end within its budget, or why not:
    /// `PermissionDenied` when it could not be read for want of permission, `ReadIncomplete` for
    /// its budget or another read error. Each case is also a gap.
    pub process_list: Observability,
    /// PID 1 is listed. When it is not in a complete list, other users' processes are hidden
    /// (`hidepid`). A list cut short says nothing about it.
    pub pid1_visible: bool,
    /// What could not be read, and might hide the runtime or its sockets: a table, the process
    /// list, a process that could not be identified.
    pub gaps: Vec<String>,
    /// What the second pass read of each runtime and descendant, by PID (PR-4d-2).
    pub details: Vec<Detail>,
    /// Why some process's parent is not known: a descendant of the runtime may be missing
    /// (PR-4d-2). Kept apart from `gaps`, which say what may hide the runtime's sockets.
    pub lineage_gaps: Vec<String>,
}

/// What the second pass read of one runtime or descendant, beyond its `ProcessObs` (PR-4d-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    pub process: ProcessRef,
    /// Its executable's `dev:ino` (`stat` through `exe`), when it could be read.
    pub exe_id: Option<(u64, u64)>,
    /// Both the executable's identity and `maps` were refused for want of permission.
    pub denied: bool,
    /// What was not observed, one entry each.
    pub missing: Vec<String>,
}

/// Why a recorded process has no mappings: it exited between the two passes.
pub const EXITED: &str = "the process exited before its executable and mappings were read";

/// When the processes were read, and in which boot: part of each one's identity.
#[derive(Clone, Copy)]
struct When<'a> {
    at: &'a Timestamp,
    boot_id: &'a str,
}

/// What the second pass shares.
struct Ctx<'a> {
    root: BorrowedFd<'a>,
    when: When<'a>,
    budgets: ProcBudgets,
    own_mnt_ns: Option<u64>,
}

/// What the second pass read of one process.
struct Second {
    /// The process as recorded, for one the listing pass did not record.
    obs: Option<ProcessObs>,
    mappings: Vec<MappingObs>,
    detail: Detail,
}

/// What the second pass found of one process.
enum Pass {
    /// It exited, is a zombie, or its PID is another process now (another start time).
    Gone,
    /// Its directory or `stat` could not be read again.
    Unreadable(NotObservable),
    Read(Box<Second>),
}

/// Whether a process is the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeMatch {
    /// With the `argv` the role rests on, recorded as it was read.
    Confirmed(Vec<Vec<u8>>),
    Rejected,
    /// Its name or arguments could not be read, so it may be.
    Unknown(String),
}

/// One process, read and closed.
struct Scanned {
    pid: u32,
    comm: Option<Vec<u8>>,
    /// Its parent and start time (`stat`), or why they cannot be read.
    lineage: Result<(u32, u64), NotObservable>,
    runtime: RuntimeMatch,
    fronting: bool,
    /// The listening sockets its fds refer to.
    listening: Vec<u64>,
    /// How its fd table was read: completely, or why not.
    fd_table: Observability,
    /// The process as recorded, when it may be needed, or why it could not be recorded.
    obs: Option<Result<ProcessObs, NotObservable>>,
}

enum Scan {
    /// It exited between the listing and the read.
    Gone,
    /// Its directory could not be opened.
    Unreadable(NotObservable),
    Read(Box<Scanned>),
}

/// Reads the process and listener tables under `proc_root` (`/proc` outside tests).
pub fn observe(proc_root: &Path, at: &Timestamp, boot_id: &str, budgets: ProcBudgets) -> ProcFacts {
    observe_with(proc_root, at, boot_id, budgets, &|| {})
}

/// As [`observe`], calling `between` after the listing pass and before the second: the tests' way
/// to change a process meanwhile.
fn observe_with(
    proc_root: &Path,
    at: &Timestamp,
    boot_id: &str,
    budgets: ProcBudgets,
    between: &dyn Fn(),
) -> ProcFacts {
    let mut facts = ProcFacts {
        processes: vec![],
        listeners: vec![],
        own_net_ns: None,
        process_list: Observability::Observed,
        pid1_visible: false,
        gaps: vec![],
        details: vec![],
        lineage_gaps: vec![],
    };
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let root = match rustix::fs::openat(rustix::fs::CWD, proc_root, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            facts.process_list = Observability::NotObservable(not_observable(e));
            facts
                .gaps
                .push(format!("the proc root cannot be opened ({e})"));
            return facts;
        }
    };
    let root = root.as_fd();
    facts.own_net_ns = rustix::fs::readlinkat(root, "self/ns/net", Vec::new())
        .ok()
        .and_then(|link| parse::link_inode(link.as_bytes(), "net"));
    let own_mnt_ns = rustix::fs::readlinkat(root, "self/ns/mnt", Vec::new())
        .ok()
        .and_then(|link| parse::link_inode(link.as_bytes(), "mnt"));
    let when = When { at, boot_id };
    let rows = read_tables(root, budgets, &mut facts.gaps);
    let listening: BTreeSet<u64> = rows.iter().map(|(_, row)| row.inode).collect();

    let (pids, process_list) = list_pids(root, budgets, &mut facts.gaps);
    facts.process_list = process_list;
    facts.pid1_visible = pids.contains(&1);
    let mut scanned: Vec<Scanned> = vec![];
    // Why some fd table was not listed completely, if one was not. A process that was not listed
    // is one; under `hidepid` (PID 1 missing from a complete list), other users' processes are.
    let mut incomplete: Option<NotObservable> = match process_list {
        Observability::NotObservable(why) => Some(why),
        Observability::Observed if !facts.pid1_visible => Some(NotObservable::PermissionDenied),
        Observability::Observed => None,
    };
    for pid in pids {
        match scan(root, pid, &listening, when, budgets) {
            Scan::Gone => {}
            Scan::Unreadable(why) => {
                facts.gaps.push(format!(
                    "process {pid} cannot be read ({why:?}); it may be the runtime"
                ));
                facts.lineage_gaps.push(format!(
                    "process {pid} cannot be read ({why:?}); its parent is not known"
                ));
                incomplete = Some(worse(incomplete, why));
            }
            Scan::Read(s) => {
                if let RuntimeMatch::Unknown(why) = &s.runtime {
                    facts
                        .gaps
                        .push(format!("process {pid} may be the runtime: {why}"));
                }
                if let (RuntimeMatch::Confirmed(_), Some(Err(why))) = (&s.runtime, &s.obs) {
                    facts.gaps.push(format!(
                        "process {pid} is the runtime but cannot be recorded ({why:?})"
                    ));
                }
                if let Observability::NotObservable(why) = s.fd_table {
                    incomplete = Some(worse(incomplete, why));
                }
                if let Err(why) = s.lineage {
                    facts.lineage_gaps.push(format!(
                        "process {pid}: its parent cannot be read ({why:?})"
                    ));
                }
                scanned.push(*s);
            }
        }
    }

    let mut holders: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, s) in scanned.iter().enumerate() {
        for inode in &s.listening {
            holders.entry(*inode).or_default().push(i);
        }
    }
    let mut recorded: BTreeMap<usize, ProcessObs> = BTreeMap::new();
    for (i, s) in scanned.iter().enumerate() {
        if let (RuntimeMatch::Confirmed(_), Some(Ok(obs))) = (&s.runtime, &s.obs) {
            recorded.insert(i, obs.clone());
        }
    }
    for (protocol, row) in rows {
        let held = holders
            .get(&row.inode)
            .map(Vec::as_slice)
            .unwrap_or_default();
        // The runtime first, then a process that may be the runtime, then a fronting one.
        let rank = |i: &usize| match (&scanned[*i].runtime, scanned[*i].fronting) {
            (RuntimeMatch::Confirmed(_), _) => Some(0),
            (RuntimeMatch::Unknown(_), _) => Some(1),
            (RuntimeMatch::Rejected, true) => Some(2),
            (RuntimeMatch::Rejected, false) => None,
        };
        let holder = held
            .iter()
            .filter_map(|i| rank(i).map(|r| (r, *i)))
            .min()
            .map(|(_, i)| i);
        let owner = match (holder, held.is_empty()) {
            // A holder that may own a recorded listener is always kept (`scan`).
            (Some(i), _) => match scanned[i].obs.clone() {
                Some(Ok(obs)) => {
                    let process = obs.process.clone();
                    recorded.insert(i, obs);
                    ListenerOwner::Process { process }
                }
                // Held, but by a process that cannot be recorded.
                Some(Err(why)) => ListenerOwner::Unknown { why },
                None => ListenerOwner::Unknown {
                    why: NotObservable::ReadIncomplete,
                },
            },
            // A known owner that is neither the runtime nor fronting: not recorded.
            (None, false) => continue,
            // No table holds it: unheld only if every table was listed completely.
            (None, true) => match incomplete {
                Some(why) => ListenerOwner::Unknown { why },
                None => ListenerOwner::Unheld,
            },
        };
        if let Some(listener) = listener(protocol, row, owner) {
            facts.listeners.push(listener);
        }
    }
    facts.listeners.sort_by(|a, b| a.id.cmp(&b.id));

    // PR-4d-2: the runtimes and their descendants, read a second time.
    between();
    let ctx = Ctx {
        root,
        when,
        budgets,
        own_mnt_ns,
    };
    let observed = descendants(&scanned);
    for (i, s) in scanned.iter().enumerate() {
        let Ok((_, start_ticks)) = s.lineage else {
            continue;
        };
        if !observed.contains(&s.pid) {
            continue;
        }
        let recorded_exe = recorded.get(&i).map(|obs| &obs.exe);
        match second(&ctx, s, start_ticks, recorded_exe) {
            Pass::Read(read) => {
                if let Some(obs) = read.obs {
                    recorded.insert(i, obs);
                }
                if let Some(obs) = recorded.get_mut(&i) {
                    obs.mappings = read.mappings;
                }
                facts.details.push(read.detail);
            }
            // A recorded process (a runtime, or a descendant recorded because it holds a
            // listener) stays recorded as the listing pass saw it, with `EXITED`. A descendant
            // not otherwise recorded is not recorded.
            Pass::Gone => {
                if let Some(obs) = recorded.get(&i) {
                    facts.details.push(Detail {
                        process: obs.process.clone(),
                        exe_id: None,
                        denied: false,
                        missing: vec![EXITED.to_string()],
                    });
                }
            }
            // Still there, but not readable: never taken as gone.
            Pass::Unreadable(why) => match recorded.get(&i) {
                Some(obs) => facts.details.push(Detail {
                    process: obs.process.clone(),
                    exe_id: None,
                    denied: why == NotObservable::PermissionDenied,
                    missing: vec![format!("the process cannot be read again ({why:?})")],
                }),
                None => facts.lineage_gaps.push(format!(
                    "process {} cannot be read again ({why:?}); a descendant is not recorded",
                    s.pid
                )),
            },
        }
    }
    facts.processes = recorded.into_values().collect();
    facts
}

/// `PermissionDenied` over any other reason, so that an unknown owner names the likelier cause.
fn worse(known: Option<NotObservable>, why: NotObservable) -> NotObservable {
    match known {
        Some(NotObservable::PermissionDenied) => NotObservable::PermissionDenied,
        _ => why,
    }
}

/// The LISTEN rows of both tables. A table not read, or a row not understood, is a gap.
fn read_tables(
    root: BorrowedFd<'_>,
    budgets: ProcBudgets,
    gaps: &mut Vec<String>,
) -> Vec<(Protocol, parse::TcpListen)> {
    let mut rows = vec![];
    for (name, protocol, v6) in [
        ("net/tcp", Protocol::Tcp, false),
        ("net/tcp6", Protocol::Tcp6, true),
    ] {
        match read_limited(root, name, budgets.max_table_bytes) {
            Ok(Read::Whole(bytes)) => {
                let mut malformed = 0;
                for line in String::from_utf8_lossy(&bytes).lines() {
                    match parse::tcp_row(line, v6) {
                        parse::TcpRow::Listen(row) => rows.push((protocol, row)),
                        parse::TcpRow::NotListen => {}
                        parse::TcpRow::Malformed => malformed += 1,
                    }
                }
                if malformed > 0 {
                    gaps.push(format!("{name}: {malformed} rows could not be read"));
                }
            }
            Ok(Read::OverLimit) => gaps.push(format!("{name} is over its budget")),
            Err(e) => gaps.push(format!("{name} cannot be read ({e})")),
        }
    }
    rows
}

fn listener(protocol: Protocol, row: parse::TcpListen, owner: ListenerOwner) -> Option<Listener> {
    let (kind, address) = match protocol {
        Protocol::Tcp => ("tcp", row.address.to_string()),
        Protocol::Tcp6 => ("tcp6", format!("[{}]", row.address)),
    };
    let id = ListenerId::new(format!(
        "listener:{kind}/{address}:{}#{}",
        row.port, row.inode
    ))
    .ok()?;
    Some(Listener {
        id,
        protocol,
        address: row.address.to_string(),
        port: row.port,
        socket_inode: row.inode,
        owner,
    })
}

/// The numeric entries of the proc root, ascending, within the budget, and whether the list was
/// read to its end.
fn list_pids(
    root: BorrowedFd<'_>,
    budgets: ProcBudgets,
    gaps: &mut Vec<String>,
) -> (Vec<u32>, Observability) {
    let dir = match rustix::fs::Dir::read_from(root) {
        Ok(dir) => dir,
        Err(e) => {
            gaps.push(format!("the process list cannot be read ({e})"));
            return (vec![], Observability::NotObservable(not_observable(e)));
        }
    };
    let mut pids = vec![];
    let mut state = Observability::Observed;
    for entry in dir {
        let Ok(entry) = entry else {
            gaps.push("the process list could not be read to the end".into());
            state = Observability::NotObservable(NotObservable::ReadIncomplete);
            break;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .ok()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pids.len() as u64 >= budgets.max_processes {
            gaps.push(format!("more than {} processes", budgets.max_processes));
            state = Observability::NotObservable(NotObservable::ReadIncomplete);
            break;
        }
        pids.push(pid);
    }
    pids.sort_unstable();
    (pids, state)
}

/// Reads one process and closes its directory.
fn scan(
    root: BorrowedFd<'_>,
    pid: u32,
    listening: &BTreeSet<u64>,
    when: When<'_>,
    budgets: ProcBudgets,
) -> Scan {
    let dir = match open_dir(root, &pid.to_string()) {
        Ok(dir) => dir,
        Err(Errno::NOENT | Errno::SRCH) => return Scan::Gone,
        Err(e) => return Scan::Unreadable(not_observable(e)),
    };
    let dir = dir.as_fd();
    let comm = match read_limited(dir, "comm", 64) {
        Ok(Read::Whole(mut bytes)) => {
            while bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            Some(bytes)
        }
        Err(Errno::NOENT | Errno::SRCH) => return Scan::Gone,
        _ => None,
    };
    // PR-4d-2: every process's parent and start time, so the runtime's descendants are found.
    let lineage = match read_limited(dir, "stat", 4096) {
        Ok(Read::Whole(bytes)) => {
            let text = String::from_utf8_lossy(&bytes);
            match (parse::stat_ppid(&text), parse::stat_start_ticks(&text)) {
                (Some(ppid), Some(start_ticks)) => Ok((ppid, start_ticks)),
                _ => Err(NotObservable::ReadIncomplete),
            }
        }
        Ok(Read::OverLimit) => Err(NotObservable::ReadIncomplete),
        Err(Errno::NOENT | Errno::SRCH) => return Scan::Gone,
        Err(e) => Err(not_observable(e)),
    };
    let (listening_held, fd_table) = match sockets(dir, listening, budgets) {
        Some(found) => found,
        None => return Scan::Gone,
    };
    let runtime = match comm.as_deref() {
        None => RuntimeMatch::Unknown("its name cannot be read".into()),
        Some(b"ollama") => runtime_match(dir),
        Some(_) => RuntimeMatch::Rejected,
    };
    let fronting = comm
        .as_deref()
        .is_some_and(|c| FRONTING.iter().any(|f| f.as_bytes() == c));
    // Kept for the runtime, and for a process that may own a recorded listener.
    let keep = matches!(runtime, RuntimeMatch::Confirmed(_))
        || (!listening_held.is_empty()
            && (fronting || matches!(runtime, RuntimeMatch::Unknown(_))));
    let obs = keep.then(|| {
        lineage.map(|(_, start_ticks)| {
            observation(
                dir,
                pid,
                start_ticks,
                comm.clone(),
                &runtime,
                fd_table,
                when,
            )
        })
    });
    Scan::Read(Box::new(Scanned {
        pid,
        comm,
        lineage,
        runtime,
        fronting,
        listening: listening_held,
        fd_table,
        obs,
    }))
}

/// `ollama serve` by its arguments, unless an `exe` that can be read is not `ollama`.
fn runtime_match(dir: BorrowedFd<'_>) -> RuntimeMatch {
    let argv = match read_limited(dir, "cmdline", 64 << 10) {
        Ok(Read::Whole(bytes)) => parse::cmdline(&bytes),
        Ok(Read::OverLimit) => {
            return RuntimeMatch::Unknown("its arguments are over 64 KiB".into())
        }
        Err(e) => return RuntimeMatch::Unknown(format!("its arguments cannot be read ({e})")),
    };
    let by_argv = argv.len() >= 2 && basename(&argv[0]) == b"ollama" && argv[1] == b"serve";
    if !by_argv {
        return RuntimeMatch::Rejected;
    }
    match exe(dir) {
        Ok((path, _)) if basename(&path) != b"ollama" => RuntimeMatch::Rejected,
        _ => RuntimeMatch::Confirmed(argv),
    }
}

/// The executable's path and whether it was deleted.
fn exe(dir: BorrowedFd<'_>) -> Result<(Vec<u8>, bool), NotObservable> {
    let link = rustix::fs::readlinkat(dir, "exe", Vec::new()).map_err(not_observable)?;
    let bytes = link.into_bytes();
    match bytes.strip_suffix(b" (deleted)") {
        Some(path) => Ok((path.to_vec(), true)),
        None => Ok((bytes, false)),
    }
}

/// The process as recorded. `argv` only for the runtime: the one its role rests on, never read
/// again.
fn observation(
    dir: BorrowedFd<'_>,
    pid: u32,
    start_ticks: u64,
    comm: Option<Vec<u8>>,
    runtime: &RuntimeMatch,
    fd_table: Observability,
    when: When<'_>,
) -> ProcessObs {
    let net_ns = match rustix::fs::readlinkat(dir, "ns/net", Vec::new()) {
        Ok(link) => match parse::link_inode(link.as_bytes(), "net") {
            Some(inode) => NsInode::Inode(inode),
            None => NsInode::NotObservable(NotObservable::ReadIncomplete),
        },
        Err(e) => NsInode::NotObservable(not_observable(e)),
    };
    let exe = match exe(dir) {
        Ok((path, deleted)) => ProcessExe::Path {
            path: UntrustedText::from_bytes(path),
            deleted,
        },
        Err(why) => ProcessExe::NotObservable(why),
    };
    // One piece of evidence: the `cmdline` read that confirmed the role.
    let (roles, argv) = match runtime {
        RuntimeMatch::Confirmed(argv) => (
            ProcessRole::new(RUNTIME_ROLE).ok().into_iter().collect(),
            Some(
                argv.iter()
                    .cloned()
                    .map(UntrustedText::from_bytes)
                    .collect(),
            ),
        ),
        _ => (vec![], None),
    };
    ProcessObs {
        process: ProcessRef {
            pid,
            start_ticks,
            boot_id: when.boot_id.to_string(),
        },
        at: when.at.clone(),
        roles,
        exe,
        mappings: vec![],
        name: comm.map(UntrustedText::from_bytes),
        argv,
        net_ns,
        fd_table,
    }
}

/// The PIDs of the confirmed runtimes, and of every process whose parent is one of them,
/// through any number of generations (PR-4d-2). Only parents read from `stat` count.
fn descendants(scanned: &[Scanned]) -> BTreeSet<u32> {
    let mut set: BTreeSet<u32> = scanned
        .iter()
        .filter(|s| matches!(s.runtime, RuntimeMatch::Confirmed(_)) && s.lineage.is_ok())
        .map(|s| s.pid)
        .collect();
    loop {
        let before = set.len();
        for s in scanned {
            if let Ok((ppid, _)) = s.lineage {
                if set.contains(&ppid) {
                    set.insert(s.pid);
                }
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

/// The second pass over one runtime or descendant (PR-4d-2): `Gone` when it exited, is a
/// zombie, or its PID is another process now (another start time); `Unreadable` when its
/// directory or `stat` cannot be read again. `recorded` is the executable the listing pass
/// recorded; for a process it did not record (`None`), its `ProcessObs` is read too.
fn second(ctx: &Ctx<'_>, s: &Scanned, start_ticks: u64, recorded: Option<&ProcessExe>) -> Pass {
    let dir = match open_dir(ctx.root, &s.pid.to_string()) {
        Ok(dir) => dir,
        Err(Errno::NOENT | Errno::SRCH) => return Pass::Gone,
        Err(e) => return Pass::Unreadable(not_observable(e)),
    };
    let dir = dir.as_fd();
    match read_limited(dir, "stat", 4096) {
        Ok(Read::Whole(bytes)) => match parse::stat_start_ticks(&String::from_utf8_lossy(&bytes)) {
            Some(ticks) if ticks == start_ticks => {}
            Some(_) => return Pass::Gone,
            None => return Pass::Unreadable(NotObservable::ReadIncomplete),
        },
        Ok(Read::OverLimit) => return Pass::Unreadable(NotObservable::ReadIncomplete),
        Err(Errno::NOENT | Errno::SRCH) => return Pass::Gone,
        Err(e) => return Pass::Unreadable(not_observable(e)),
    }
    let process = ProcessRef {
        pid: s.pid,
        start_ticks,
        boot_id: ctx.when.boot_id.to_string(),
    };
    let mut missing = vec![];
    let exe_id = exe_identity(dir);
    match exe_id {
        // Same start time, but no executable: a zombie, or it exited meanwhile.
        Err(NotObservable::NoProcess) => return Pass::Gone,
        Err(why) => missing.push(format!("exe: its identity cannot be read ({why:?})")),
        Ok(_) => {}
    }
    let same_mount_ns = mount_ns(dir, ctx.own_mnt_ns, &mut missing);
    let (mut mappings, maps_denied) = mappings(dir, &process, ctx, &same_mount_ns, &mut missing);
    let denied = exe_id == Err(NotObservable::PermissionDenied) && maps_denied;
    let mut exe_id = exe_id.ok();
    // An exec keeps the start time. Read last, so that one before or during the reads above is
    // seen: another executable than the one recorded means they are the new image's, not kept.
    // The path only: `deleted` may change meanwhile.
    if let Some(ProcessExe::Path { path, .. }) = recorded {
        if matches!(exe(dir), Ok((now, _)) if now != path.as_bytes()) {
            missing.push("exe: the process runs another executable than when it was listed".into());
            exe_id = None;
            mappings.clear();
        }
    }
    let obs = recorded.is_none().then(|| {
        observation(
            dir,
            s.pid,
            start_ticks,
            s.comm.clone(),
            &s.runtime,
            s.fd_table,
            ctx.when,
        )
    });
    Pass::Read(Box::new(Second {
        obs,
        mappings,
        detail: Detail {
            process,
            exe_id,
            denied,
            missing,
        },
    }))
}

/// The executable's `dev:ino`: `stat` through the `exe` link, which the kernel resolves to the
/// file the process runs, also when it was deleted or is in another mount namespace. The file is
/// not opened.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn exe_identity(dir: BorrowedFd<'_>) -> Result<(u64, u64), NotObservable> {
    let st = rustix::fs::statat(dir, "exe", AtFlags::empty()).map_err(not_observable)?;
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Whether the process's mount namespace is SIGIL's: what a mapping's path means (PR-4d-2).
fn mount_ns(dir: BorrowedFd<'_>, own: Option<u64>, missing: &mut Vec<String>) -> Tri<()> {
    let unknown = |why| Tri::Unknown {
        reason: UnknownReason::NotObservable(why),
    };
    let theirs = match rustix::fs::readlinkat(dir, "ns/mnt", Vec::new()) {
        Ok(link) => match parse::link_inode(link.as_bytes(), "mnt") {
            Some(inode) => inode,
            None => {
                missing.push("ns/mnt: not understood".into());
                return unknown(NotObservable::ReadIncomplete);
            }
        },
        Err(e) => {
            let why = not_observable(e);
            missing.push(format!("ns/mnt: cannot be read ({why:?})"));
            return unknown(why);
        }
    };
    let Some(ours) = own else {
        missing.push("ns/mnt: SIGIL's own cannot be read".into());
        return unknown(NotObservable::ReadIncomplete);
    };
    let basis = Basis::Observed {
        source: ObsSource::Proc,
    };
    if theirs == ours {
        Tri::Yes {
            why: (),
            basis,
            unresolved: vec![],
        }
    } else {
        Tri::No {
            basis,
            unresolved: vec![],
        }
    }
}

/// The file-backed objects of `maps`, each once, in the order first seen, and whether `maps`
/// was refused for want of permission (PR-4d-2).
fn mappings(
    dir: BorrowedFd<'_>,
    process: &ProcessRef,
    ctx: &Ctx<'_>,
    same_mount_ns: &Tri<()>,
    missing: &mut Vec<String>,
) -> (Vec<MappingObs>, bool) {
    let limit = ctx.budgets.max_maps_bytes;
    let (bytes, over) = match read_up_to(dir, "maps", limit) {
        Ok(read) => read,
        Err(e) => {
            let why = not_observable(e);
            missing.push(format!("maps: cannot be read ({why:?})"));
            return (vec![], why == NotObservable::PermissionDenied);
        }
    };
    let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    if over {
        // The last line may be cut: it is not read.
        lines.pop();
        missing.push(format!("maps: over proc_maps_bytes ({limit} bytes read)"));
    }
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    let mut malformed = 0usize;
    for line in lines.into_iter().filter(|l| !l.is_empty()) {
        match parse::maps_row(line) {
            parse::MapsRow::File(m) => {
                if seen.insert((m.dev, m.ino, m.path.clone(), m.deleted)) {
                    out.push(MappingObs {
                        process: process.clone(),
                        at: ctx.when.at.clone(),
                        dev: m.dev,
                        ino: m.ino,
                        path_text: UntrustedText::from_bytes(m.path),
                        deleted: m.deleted,
                        instance: None,
                        same_mount_ns: same_mount_ns.clone(),
                    });
                }
            }
            parse::MapsRow::NotFile => {}
            parse::MapsRow::Malformed => malformed += 1,
        }
    }
    if malformed > 0 {
        missing.push(format!("maps: {malformed} lines not understood"));
    }
    (out, false)
}

/// The listening sockets a process's fds refer to, and whether its fd table was listed
/// completely. `None` when it exited meanwhile.
fn sockets(
    dir: BorrowedFd<'_>,
    listening: &BTreeSet<u64>,
    budgets: ProcBudgets,
) -> Option<(Vec<u64>, Observability)> {
    let fds = match open_dir(dir, "fd") {
        Ok(fds) => fds,
        Err(Errno::NOENT | Errno::SRCH) => return None,
        Err(e) => return Some((vec![], Observability::NotObservable(not_observable(e)))),
    };
    let incomplete = Observability::NotObservable(NotObservable::ReadIncomplete);
    let Ok(entries) = rustix::fs::Dir::read_from(fds.as_fd()) else {
        return Some((vec![], incomplete));
    };
    let mut held = vec![];
    let mut count: u64 = 0;
    let mut state = Observability::Observed;
    for entry in entries {
        let Ok(entry) = entry else {
            state = incomplete;
            break;
        };
        let Ok(name) = entry.file_name().to_str() else {
            state = incomplete;
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        count += 1;
        if count > budgets.max_fds {
            state = incomplete;
            break;
        }
        match rustix::fs::readlinkat(fds.as_fd(), name, Vec::new()) {
            Ok(link) => {
                if let Some(inode) = parse::link_inode(link.as_bytes(), "socket") {
                    if listening.contains(&inode) {
                        held.push(inode);
                    }
                }
            }
            // Closed meanwhile: not a socket it holds.
            Err(Errno::NOENT) => {}
            Err(_) => state = incomplete,
        }
    }
    Some((held, state))
}

fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|b| *b == b'/').next().unwrap_or(path)
}

fn not_observable(e: Errno) -> NotObservable {
    match e {
        Errno::ACCESS | Errno::PERM => NotObservable::PermissionDenied,
        Errno::NOENT | Errno::SRCH => NotObservable::NoProcess,
        _ => NotObservable::ReadIncomplete,
    }
}

fn open_dir(dir: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

enum Read {
    Whole(Vec<u8>),
    OverLimit,
}

/// Reads `name` in `dir` (its last component not followed), up to `limit` bytes. procfs reports
/// no size, so the limit is checked while reading.
fn read_limited(dir: BorrowedFd<'_>, name: &str, limit: u64) -> Result<Read, Errno> {
    let (bytes, over) = read_up_to(dir, name, limit)?;
    Ok(if over {
        Read::OverLimit
    } else {
        Read::Whole(bytes)
    })
}

/// Reads `name` in `dir` (not followed) up to `limit` bytes, and whether it holds more: then the
/// first `limit` bytes are returned.
fn read_up_to(dir: BorrowedFd<'_>, name: &str, limit: u64) -> Result<(Vec<u8>, bool), Errno> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut out = vec![];
    let mut buffer = [0u8; 8192];
    loop {
        let n = match rustix::io::read(&fd, &mut buffer) {
            Ok(0) => return Ok((out, false)),
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        };
        out.extend_from_slice(&buffer[..n]);
        if out.len() as u64 > limit {
            out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            return Ok((out, true));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    use sigil_model::{ProcessRef, Timestamp};

    use super::{observe_with, Detail, ProcBudgets, ProcFacts, EXITED};

    /// A process directory. Its `exe` links to a file of the fixture, `<root>/fs/<comm>`.
    fn process(root: &Path, pid: u32, ppid: u32, comm: &str, argv: &[&str], start: u64) {
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).unwrap();
        std::fs::create_dir_all(dir.join("ns")).unwrap();
        std::fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
        let mut cmdline = vec![];
        for a in argv {
            cmdline.extend_from_slice(a.as_bytes());
            cmdline.push(0);
        }
        std::fs::write(dir.join("cmdline"), cmdline).unwrap();
        let fields: Vec<String> = (5..=21).map(|n| n.to_string()).collect();
        std::fs::write(
            dir.join("stat"),
            format!("{pid} ({comm}) S {ppid} {} {start} 0 0\n", fields.join(" ")),
        )
        .unwrap();
        std::fs::write(dir.join("maps"), "").unwrap();
        symlink("net:[1]", dir.join("ns/net")).unwrap();
        symlink("mnt:[2]", dir.join("ns/mnt")).unwrap();
        let exe = root.join("fs").join(comm);
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, comm).unwrap();
        symlink(&exe, dir.join("exe")).unwrap();
    }

    /// A proc root with PID 1, `ollama serve` as PID 10 (start 100), and its child 11 (start 200).
    fn fixture(root: &Path) {
        std::fs::create_dir_all(root.join("self/ns")).unwrap();
        std::fs::create_dir_all(root.join("net")).unwrap();
        std::fs::write(root.join("net/tcp"), "").unwrap();
        std::fs::write(root.join("net/tcp6"), "").unwrap();
        symlink("net:[1]", root.join("self/ns/net")).unwrap();
        symlink("mnt:[2]", root.join("self/ns/mnt")).unwrap();
        process(root, 1, 0, "init", &["/sbin/init"], 1);
        process(root, 10, 1, "ollama", &["/x/ollama", "serve"], 100);
        process(root, 11, 10, "runner", &["/x/runner"], 200);
    }

    fn run(root: &Path, between: &dyn Fn()) -> ProcFacts {
        let at = Timestamp::new("2026-11-01T00:00:00Z").unwrap();
        observe_with(root, &at, "b", ProcBudgets::default(), between)
    }

    fn pids(f: &ProcFacts) -> Vec<u32> {
        f.processes.iter().map(|p| p.process.pid).collect()
    }

    fn detail(f: &ProcFacts, pid: u32) -> &Detail {
        f.details
            .iter()
            .find(|d| d.process.pid == pid)
            .unwrap_or_else(|| panic!("no detail for {pid}: {:?}", f.details))
    }

    /// A descendant whose PID is another process by the second pass (another start time) is
    /// not recorded.
    #[test]
    fn a_pid_reused_between_the_passes_is_not_recorded() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        let f = run(root, &|| {
            std::fs::remove_dir_all(root.join("11")).unwrap();
            process(root, 11, 10, "runner", &["/x/runner"], 300);
        });
        assert_eq!(pids(&f), [10]);
        assert_eq!(f.details.len(), 1);
    }

    /// Review of PR-4d-2: a descendant that cannot be read again is not dropped silently.
    #[test]
    fn a_descendant_that_cannot_be_read_again_is_a_lineage_gap() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        let stat = root.join("11/stat");
        let f = run(root, &|| {
            std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o000)).unwrap();
        });
        if std::fs::read(&stat).is_ok() {
            eprintln!("skipped: root reads a mode-000 file");
            return;
        }
        assert_eq!(pids(&f), [10]);
        assert_eq!(
            f.lineage_gaps,
            ["process 11 cannot be read again (PermissionDenied); a descendant is not recorded"]
        );
        assert_eq!(f.details.len(), 1);
    }

    /// A runtime gone by the second pass stays recorded as the listing pass saw it.
    #[test]
    fn a_runtime_gone_by_the_second_pass_stays_recorded_as_exited() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        let f = run(root, &|| std::fs::remove_dir_all(root.join("10")).unwrap());
        assert_eq!(pids(&f), [10, 11]);
        assert!(f.processes[0].mappings.is_empty());
        assert_eq!(
            *detail(&f, 10),
            Detail {
                process: ProcessRef {
                    pid: 10,
                    start_ticks: 100,
                    boot_id: "b".to_string(),
                },
                exe_id: None,
                denied: false,
                missing: vec![EXITED.to_string()],
            }
        );
    }

    /// A zombie keeps its `stat` (and start time), but its `exe` no longer resolves: it is gone.
    #[test]
    fn a_descendant_whose_exe_no_longer_resolves_is_gone() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        let exe = root.join("11/exe");
        let f = run(root, &|| {
            std::fs::remove_file(&exe).unwrap();
            symlink(root.join("fs/deleted"), &exe).unwrap();
        });
        assert_eq!(pids(&f), [10]);
        assert_eq!(f.details.len(), 1);
        assert!(f.lineage_gaps.is_empty(), "{:?}", f.lineage_gaps);
    }

    /// Review of PR-4d-2: an exec keeps the start time. When the runtime runs another executable
    /// by the second pass, its identity and mappings are the new image's: not kept.
    #[test]
    fn an_exec_between_the_passes_keeps_no_identity_or_mappings() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        std::fs::write(
            root.join("10/maps"),
            "7f0000000000-7f0000001000 r-xp 00000000 08:01 1234 /x/lib.so\n",
        )
        .unwrap();
        let other = root.join("fs/other/ollama");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, b"other").unwrap();
        let exe = root.join("10/exe");
        let f = run(root, &|| {
            std::fs::remove_file(&exe).unwrap();
            symlink(&other, &exe).unwrap();
        });
        assert_eq!(pids(&f), [10, 11]);
        assert!(f.processes[0].mappings.is_empty(), "{:?}", f.processes[0]);
        let d = detail(&f, 10);
        assert_eq!(d.exe_id, None);
        assert_eq!(
            d.missing,
            ["exe: the process runs another executable than when it was listed"]
        );
    }
}
