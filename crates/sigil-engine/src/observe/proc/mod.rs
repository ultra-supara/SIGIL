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
//!   processes whose `comm` is `ollama`, and the argv recorded for the runtime is the one read
//!   its role rests on; the second pass reads the runtime's again only to compare (PR-4d-2). A
//!   process whose name or arguments cannot be read may be the runtime: it is a gap, and the
//!   listeners it holds are kept. So is the runtime when it cannot be recorded (its `stat`); the
//!   listeners it holds are kept with an `Unknown` owner.
//!
//! Processes are read one at a time, and each one's directory is closed before the next, so the
//! number of open files does not grow with the process table.
//!
//! **The runtime's descendants (PR-4d-2).** Every listed process's `stat` gives its parent; the
//! runtimes and every process descended from one are read a second time, after checking that
//! the PID is still the process listed (its start time): the executable's `dev:ino` (`stat`
//! through `exe`, which follows the link to the file the process runs and never opens it),
//! `maps` up to `proc_maps_bytes` (and `proc_maps_total_bytes` over all of them), and `ns/mnt`.
//! A mapping is one per distinct (dev, ino, path, deleted): one inode reached by two paths gives
//! two. It is an observation only: nothing is derived from one, or from its absence (F-T1). An
//! exec keeps the PID and the start time: the executable's path and identity (the runtime's
//! also read by the listing pass), and the runtime's arguments, are read again after `maps`, and
//! what was read is dropped when one changed (`second`).
//! Linking them to scanned files is `analyze::runtime_processes`. A listener's holder outside the
//! runtime's tree is not read again; one that may be the runtime gets a [`Detail`] saying so.
//!
//! Every entry read is in the C-6 allowlist: `net/tcp{,6}`, the proc root's directory,
//! `self/ns/{net,mnt}`, and, per process, `comm`, `cmdline`, `stat`, `exe` (`readlinkat`, and
//! `stat` through it), `maps`, `ns/net`, `ns/mnt`, `fd`, and `fd/<n>`. No link but `exe` is
//! followed, and nothing it leads to is opened.

pub mod parse;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use sigil_model::{
    Basis, Listener, ListenerId, ListenerOwner, MappingObs, MapsRead, NotObservable, NsInode,
    ObsSource, Observability, ProcessExe, ProcessObs, ProcessRef, ProcessRole, Protocol, Timestamp,
    Tri, UnknownReason, UntrustedText,
};

/// The role of the runtime's server process.
pub use sigil_model::RUNTIME_ROLE;
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
    /// Bytes of `maps` over all processes of one observation (PR-4d-2).
    pub max_maps_total_bytes: u64,
}

impl Default for ProcBudgets {
    fn default() -> Self {
        ProcBudgets {
            max_processes: 32_768,
            max_fds: 65_536,
            max_table_bytes: 16 << 20,
            max_maps_bytes: 16 << 20,
            max_maps_total_bytes: 256 << 20,
        }
    }
}

/// What was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcFacts {
    /// The runtime processes, the processes that hold a recorded listener, and the runtimes'
    /// descendants (PR-4d-2), by PID.
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
    /// What the second pass read of each runtime and descendant, by PID, then what was not read
    /// of each listener's holder outside the runtime's tree that may be the runtime (PR-4d-2).
    pub details: Vec<Detail>,
    /// What may hide a runtime or a descendant from the second pass: a process that cannot be
    /// read or read again, whose parent cannot be read, or that may be the runtime (PR-4d-2).
    /// Kept apart from `gaps`, which say what may hide the runtime's sockets.
    pub process_gaps: Vec<String>,
    /// The recorded processes the second pass did not read, by PID: listeners' holders not found
    /// among the runtime and its descendants, and not the runtime as far as was read (PR-4d-2).
    /// Each one's `processes.observed` is `OutOfScope`. A holder that may be the runtime has a
    /// [`Detail`] instead.
    pub outside: Vec<ProcessRef>,
}

/// What the second pass read of one runtime or descendant, beyond its `ProcessObs`; or, for a
/// listener's holder outside the runtime's tree that may be the runtime, that nothing was
/// (PR-4d-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    pub process: ProcessRef,
    /// Its executable's `dev:ino` (`stat` through `exe`), when it could be read and the process
    /// was not seen to run another program meanwhile.
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
    /// The bytes of `maps` still to be read in this observation (`max_maps_total_bytes`).
    maps_left: Cell<u64>,
}

/// What the second pass read of one process.
struct Second {
    /// The process as recorded, for one the listing pass did not record.
    obs: Option<ProcessObs>,
    mappings: Vec<MappingObs>,
    /// How much of `maps` `mappings` stands for.
    maps_read: MapsRead,
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
    /// For a confirmed runtime only, its executable's `dev:ino` (`stat` through `exe`) or why it
    /// cannot be read: what the second pass compares its own reads with (PR-4d-2).
    exe_id: Option<Result<(u64, u64), NotObservable>>,
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
        process_gaps: vec![],
        outside: vec![],
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
                facts.process_gaps.push(format!(
                    "process {pid} cannot be read ({why:?}); its parent is not known"
                ));
                incomplete = Some(worse(incomplete, why));
            }
            Scan::Read(s) => {
                if let RuntimeMatch::Unknown(why) = &s.runtime {
                    // Its executable and descendants were not observed, if it is the runtime.
                    let gap = format!("process {pid} may be the runtime: {why}");
                    facts.gaps.push(gap.clone());
                    facts.process_gaps.push(gap);
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
                    facts.process_gaps.push(format!(
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
        maps_left: Cell::new(budgets.max_maps_total_bytes),
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
                    obs.maps_read = read.maps_read;
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
                None => facts.process_gaps.push(format!(
                    "process {} cannot be read again ({why:?}); a descendant is not recorded",
                    s.pid
                )),
            },
        }
    }
    // Code review of PR-4d-2, R-C: a recorded process outside the runtime's tree holds a
    // listener (`scan`), and the second pass did not read it. One that may be the runtime is a
    // gap if it is; any other is outside the check's scope.
    for (i, obs) in &recorded {
        // Read by the second pass, which gave it its `Detail`.
        if observed.contains(&scanned[*i].pid) {
            continue;
        }
        match &scanned[*i].runtime {
            RuntimeMatch::Unknown(why) => facts.details.push(Detail {
                process: obs.process.clone(),
                exe_id: None,
                denied: false,
                missing: vec![format!(
                    "the process may be the runtime ({why}); its executable and mappings were not read"
                )],
            }),
            RuntimeMatch::Rejected => facts.outside.push(obs.process.clone()),
            // A recorded runtime has a readable parent, so it is always in its own tree. Were it
            // not, it gets no entry, which validation refuses, never `OutOfScope`.
            RuntimeMatch::Confirmed(_) => {}
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
    // Code review of PR-4d-2, R-B: an exec of another file at the same path keeps the path, so
    // the second pass also compares the runtime's executable identity with the one listed here.
    let exe_id = matches!(runtime, RuntimeMatch::Confirmed(_)).then(|| exe_identity(dir));
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
        exe_id,
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

/// The process as recorded. `argv` only for the runtime: the one its role rests on, which the
/// second pass reads again only to compare (`argv_changed`).
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
        // Until the second pass reads `maps`, if it does.
        maps_read: MapsRead::NotRead,
        name: comm.map(UntrustedText::from_bytes),
        argv,
        net_ns,
        fd_table,
    }
}

/// The PIDs of the confirmed runtimes, and of every process whose parent is one of them,
/// through any number of generations (PR-4d-2), breadth first. Only parents read from `stat`
/// count.
fn descendants(scanned: &[Scanned]) -> BTreeSet<u32> {
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for s in scanned {
        if let Ok((ppid, _)) = s.lineage {
            children.entry(ppid).or_default().push(s.pid);
        }
    }
    let mut set: BTreeSet<u32> = scanned
        .iter()
        .filter(|s| matches!(s.runtime, RuntimeMatch::Confirmed(_)) && s.lineage.is_ok())
        .map(|s| s.pid)
        .collect();
    let mut queue: VecDeque<u32> = set.iter().copied().collect();
    while let Some(pid) = queue.pop_front() {
        for &child in children.get(&pid).map(Vec::as_slice).unwrap_or_default() {
            if set.insert(child) {
                queue.push_back(child);
            }
        }
    }
    set
}

/// The second pass over one runtime or descendant (PR-4d-2): `Gone` when it exited, is a
/// zombie, or its PID is another process now (another start time); `Unreadable` when its
/// directory or `stat` cannot be read again. `recorded` is the executable the listing pass
/// recorded; for a process it did not record (`None`), its `ProcessObs` is read too, and the
/// path it records is the one last read.
///
/// An exec keeps the PID and the start time, and an exec of the same path keeps the path too.
/// The reads are, in order: `stat`; the executable's path, then its identity (a zombie is gone
/// here); `ns/mnt`; `maps`; the identity again; the path again; and, for the runtime, `cmdline`
/// again. What was read is taken as another program's, and its identity and mappings are
/// dropped (`maps` counts as not read), when:
/// - the path changed since the listing pass, or between its two reads (`exec_seen`);
/// - the identity changed between its two reads, or since the listing pass read the runtime's
///   (`identity_changed`);
/// - the runtime's arguments are not the ones its role rests on (`argv_changed`).
///
/// The role and the argv recorded at listing are kept: they held then, and the gap says that
/// this pass may have read another program.
///
/// Code review of PR-4d-2, R-B: several `/proc` reads are not one atomic snapshot. SIGIL checks
/// that the executable's path and identity, and for the runtime its arguments, are the same
/// before and after `maps`. An exec of the same file with the same arguments between those reads
/// cannot be told apart; what the session states (that file, those arguments, those mappings at
/// `at`) still holds of the process then.
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
    // An exec keeps the start time, so the executable's path and identity are read before the
    // reads below and again after them.
    let first = exe(dir).ok().map(|(path, _)| path);
    let first_id = exe_identity(dir);
    if let Err(why) = first_id {
        // `exe` gives `ENOENT` for a zombie or a process gone meanwhile, but also for a live one
        // whose executable's file system no longer resolves it (FUSE `hard_remove`).
        if why == NotObservable::NoProcess && exited(dir) {
            return Pass::Gone;
        }
        missing.push(format!("exe: its identity cannot be read ({why:?})"));
    }
    let same_mount_ns = mount_ns(dir, ctx.own_mnt_ns, &mut missing);
    let (mut mappings, mut maps_read, maps_denied) =
        mappings(dir, &process, ctx, &same_mount_ns, &mut missing);
    let denied = first_id == Err(NotObservable::PermissionDenied) && maps_denied;
    let again_id = exe_identity(dir);
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
    // The path read last: for a process not recorded before, the one `observation` records.
    let last = match &obs {
        Some(obs) => match &obs.exe {
            ProcessExe::Path { path, .. } => Some(path.as_bytes().to_vec()),
            _ => None,
        },
        None => exe(dir).ok().map(|(path, _)| path),
    };
    // Code review of PR-4d-2, R-B: `ollama serve` re-exec'd as `ollama version` keeps the path,
    // and the file too, but not its arguments.
    let other_argv = match &s.runtime {
        RuntimeMatch::Confirmed(argv) => argv_changed(argv, read_limited(dir, "cmdline", 64 << 10)),
        _ => false,
    };
    let other_exe = exec_seen(recorded, first.as_deref(), last.as_deref())
        || identity_changed(s.exe_id.as_ref(), &first_id, &again_id);
    if other_exe {
        missing.push(
            "exe: the process ran another executable (its path or identity changed) since it was \
             listed or during the reads"
                .into(),
        );
    }
    if other_argv {
        missing.push(
            "cmdline: the runtime's arguments changed, or cannot be read again, since it was \
             listed"
                .into(),
        );
    }
    let exe_id = if other_exe || other_argv {
        // What was read may be another program's: dropped, so not read.
        mappings.clear();
        maps_read = MapsRead::NotRead;
        None
    } else {
        first_id.ok()
    };
    Pass::Read(Box::new(Second {
        obs,
        mappings,
        maps_read,
        detail: Detail {
            process,
            exe_id,
            denied,
            missing,
        },
    }))
}

/// Whether the process ran another executable at some read of its path (`first`, before the
/// second pass's reads, and `last`, after them) than the one expected: the path recorded by the
/// listing pass, or else the first one read. Then what was read in between may be another
/// image's (an exec keeps the start time). The path only: `deleted` may change meanwhile. An
/// exec of the same path is not seen here, but by `identity_changed` when the file changed, and
/// by `argv_changed` when the runtime's arguments did.
fn exec_seen(recorded: Option<&ProcessExe>, first: Option<&[u8]>, last: Option<&[u8]>) -> bool {
    let expected = match recorded {
        Some(ProcessExe::Path { path, .. }) => Some(path.as_bytes()),
        _ => first,
    };
    expected.is_some_and(|want| [first, last].into_iter().flatten().any(|path| path != want))
}

/// Whether the executable's identity changed (code review of PR-4d-2, R-B): the second pass's
/// two reads of it (`first`, before `maps`, and `again`, after it) differ as read, an error
/// being a reading too; or the listing pass read one (`listed`, for the runtime only) and
/// `first` is not that one. An error counts there too: a setuid exec makes the process
/// non-dumpable, and `exe` then gives `EACCES`. A listing that read no identity says nothing.
fn identity_changed(
    listed: Option<&Result<(u64, u64), NotObservable>>,
    first: &Result<(u64, u64), NotObservable>,
    again: &Result<(u64, u64), NotObservable>,
) -> bool {
    let since_listing = matches!(listed, Some(Ok(id)) if *first != Ok(*id));
    since_listing || first != again
}

/// Whether the runtime's arguments, read again after its `maps` (`again`, up to 64 KiB as the
/// listing pass reads them), are not the ones its role rests on (`listed`): `cmdline` cannot be
/// read, is over 64 KiB, or does not parse to exactly them (code review of PR-4d-2, R-B).
fn argv_changed(listed: &[Vec<u8>], again: Result<Read, Errno>) -> bool {
    match again {
        Ok(Read::Whole(bytes)) => parse::cmdline(&bytes) != listed,
        Ok(Read::OverLimit) | Err(_) => true,
    }
}

/// Whether the process is a zombie or gone, by its `stat` read again (PR-4d-2): gone, or in
/// state `Z` or `X`.
fn exited(dir: BorrowedFd<'_>) -> bool {
    match read_limited(dir, "stat", 4096) {
        Ok(Read::Whole(bytes)) => matches!(
            parse::stat_state(&String::from_utf8_lossy(&bytes)),
            Some(b'Z' | b'X')
        ),
        Ok(Read::OverLimit) => false,
        Err(e) => matches!(e, Errno::NOENT | Errno::SRCH),
    }
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

/// The file-backed mappings of `maps`, one per distinct (dev, ino, path, deleted) in the order
/// first seen (one inode reached by two paths gives two), how much of `maps` they stand for, and
/// whether `maps` was refused for want of permission (PR-4d-2). It is read up to
/// `max_maps_bytes`, and no more than what is left of `max_maps_total_bytes`: `NotRead` when it
/// cannot be read or nothing is left, `Part` when it is over a budget or has lines not
/// understood, and `NotRead` again when such a read kept no mapping. One read to its end is
/// `Whole`, mappings or none.
fn mappings(
    dir: BorrowedFd<'_>,
    process: &ProcessRef,
    ctx: &Ctx<'_>,
    same_mount_ns: &Tri<()>,
    missing: &mut Vec<String>,
) -> (Vec<MappingObs>, MapsRead, bool) {
    let per_process = ctx.budgets.max_maps_bytes;
    let remaining = ctx.maps_left.get();
    if remaining == 0 {
        missing.push("maps: not read (proc_maps_total_bytes reached)".into());
        return (vec![], MapsRead::NotRead, false);
    }
    let limit = per_process.min(remaining);
    let (bytes, over) = match read_up_to(dir, "maps", limit) {
        Ok(read) => read,
        Err(e) => {
            let why = not_observable(e);
            missing.push(format!("maps: cannot be read ({why:?})"));
            return (
                vec![],
                MapsRead::NotRead,
                why == NotObservable::PermissionDenied,
            );
        }
    };
    ctx.maps_left
        .set(remaining.saturating_sub(bytes.len() as u64));
    let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    if over {
        // The last line may be cut: it is not read.
        lines.pop();
        if limit < per_process {
            missing.push(format!(
                "maps: over proc_maps_total_bytes ({remaining} bytes were left)"
            ));
        } else {
            missing.push(format!("maps: over proc_maps_bytes ({limit} bytes read)"));
        }
    }
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    let mut malformed = 0usize;
    for line in lines.into_iter().filter(|l| !l.is_empty()) {
        match parse::maps_row(line) {
            parse::MapsRow::File(m) => {
                // One per distinct (dev, ino, path, deleted), not per VMA.
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
    // A read in part that kept no mapping is no count at all (review of R1): its gaps say why.
    let read = match (over || malformed > 0, out.is_empty()) {
        (false, _) => MapsRead::Whole,
        (true, false) => MapsRead::Part,
        (true, true) => MapsRead::NotRead,
    };
    (out, read, false)
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
/// first `limit` bytes are returned. No more than `limit + 1` bytes are ever read.
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
        let want = request(out.len(), limit, buffer.len());
        let n = match rustix::io::read(&fd, &mut buffer[..want]) {
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

/// How many bytes one `read(2)` asks for, when `read` bytes were read up to `limit`: no more
/// than the buffer holds, and no more than `limit + 1` in all (the one byte more shows that there
/// is more). Never 0 while under `limit + 1`.
fn request(read: usize, limit: u64, buffer: usize) -> usize {
    let left = limit.saturating_add(1).saturating_sub(read as u64);
    usize::try_from(left).unwrap_or(usize::MAX).min(buffer)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::Path;

    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;
    use sigil_model::{
        MapsRead, NotObservable, ProcessExe, ProcessRef, ProcessRole, Timestamp, UntrustedText,
    };

    use super::{
        argv_changed, exec_seen, identity_changed, observe_with, read_up_to, request, Detail,
        ProcBudgets, ProcFacts, Read, EXITED, RUNTIME_ROLE,
    };

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
        stat(root, pid, ppid, comm, 'S', start);
        std::fs::write(dir.join("maps"), "").unwrap();
        symlink("net:[1]", dir.join("ns/net")).unwrap();
        symlink("mnt:[2]", dir.join("ns/mnt")).unwrap();
        let exe = root.join("fs").join(comm);
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, comm).unwrap();
        symlink(&exe, dir.join("exe")).unwrap();
    }

    /// Writes a process's `stat`, in state `state`.
    fn stat(root: &Path, pid: u32, ppid: u32, comm: &str, state: char, start: u64) {
        let fields: Vec<String> = (5..=21).map(|n| n.to_string()).collect();
        std::fs::write(
            root.join(pid.to_string()).join("stat"),
            format!(
                "{pid} ({comm}) {state} {ppid} {} {start} 0 0\n",
                fields.join(" ")
            ),
        )
        .unwrap();
    }

    /// Points a process's `exe` at a file that does not exist: `stat` through it gives `ENOENT`.
    fn dangle(root: &Path, pid: u32) {
        let exe = root.join(pid.to_string()).join("exe");
        std::fs::remove_file(&exe).unwrap();
        symlink(root.join("fs/deleted"), &exe).unwrap();
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
        // Gone, not unreadable: no gap.
        assert!(f.process_gaps.is_empty(), "{:?}", f.process_gaps);
    }

    /// Review of PR-4d-2: a descendant that cannot be read again is not dropped silently.
    #[test]
    fn a_descendant_that_cannot_be_read_again_is_a_process_gap() {
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
            f.process_gaps,
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
        assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
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

    /// A zombie (or a dead process) keeps its `stat` and start time, but its `exe` no longer
    /// resolves: it is gone.
    #[test]
    fn a_zombie_descendant_is_gone() {
        for state in ['Z', 'X'] {
            let d = tempfile::TempDir::new().unwrap();
            let root = d.path();
            fixture(root);
            let f = run(root, &|| {
                dangle(root, 11);
                stat(root, 11, 10, "runner", state, 200);
            });
            assert_eq!(pids(&f), [10], "{state}");
            assert_eq!(f.details.len(), 1, "{state}");
            assert!(f.process_gaps.is_empty(), "{state}: {:?}", f.process_gaps);
        }
    }

    /// Review of PR-4d-2: `exe` also gives `ENOENT` for a live process whose executable's file
    /// system no longer resolves it (FUSE `hard_remove`). Live by its state, it is recorded, and
    /// its identity is a gap.
    #[test]
    fn a_live_descendant_whose_exe_no_longer_resolves_is_recorded_with_a_gap() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        let f = run(root, &|| dangle(root, 11));
        assert_eq!(pids(&f), [10, 11]);
        let d = detail(&f, 11);
        assert_eq!(d.exe_id, None);
        assert_eq!(d.missing, ["exe: its identity cannot be read (NoProcess)"]);
    }

    /// Re-review of PR-4d-2: a runtime still there but not readable again stays recorded, and
    /// says why; its child is still observed.
    #[test]
    fn a_runtime_that_cannot_be_read_again_stays_recorded_and_says_why() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        let stat = root.join("10/stat");
        let f = run(root, &|| {
            std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o000)).unwrap();
        });
        if std::fs::read(&stat).is_ok() {
            eprintln!("skipped: root reads a mode-000 file");
            return;
        }
        assert_eq!(pids(&f), [10, 11]);
        assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
        let d = detail(&f, 10);
        assert!(d.denied, "{d:?}");
        assert_eq!(
            d.missing,
            ["the process cannot be read again (PermissionDenied)"]
        );
    }

    /// Re-review of PR-4d-2: the reads of the second pass are the image of one executable only
    /// when every read of its path names it: the recorded one, or else the first read.
    #[test]
    fn an_exec_is_seen_by_any_read_of_the_path() {
        let path = |p: &str| ProcessExe::Path {
            path: UntrustedText::new(p),
            deleted: false,
        };
        let unknown = ProcessExe::NotObservable(NotObservable::PermissionDenied);
        let (a, b): (&[u8], &[u8]) = (b"/a", b"/b");
        for (recorded, first, last, seen) in [
            // Not recorded by the listing pass: the first read is the expected path.
            (None, Some(a), Some(b), true),
            (None, Some(a), Some(a), false),
            (None, None, Some(b), false),
            (Some(&unknown), Some(a), Some(b), true),
            (Some(&unknown), Some(a), Some(a), false),
            // Recorded: its path is.
            (Some(&path("/a")), Some(a), Some(b), true),
            (Some(&path("/a")), Some(b), Some(b), true),
            (Some(&path("/a")), Some(b), Some(a), true),
            (Some(&path("/a")), Some(a), Some(a), false),
            (Some(&path("/a")), None, None, false),
        ] {
            assert_eq!(
                exec_seen(recorded, first, last),
                seen,
                "{recorded:?} {first:?} {last:?}"
            );
        }
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
        // Code review of PR-4d-2, R-A: what was read is dropped, so `maps` counts as not read.
        assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
        let d = detail(&f, 10);
        assert_eq!(d.exe_id, None);
        assert_eq!(
            d.missing,
            ["exe: the process ran another executable (its path or identity changed) since it was listed or during the reads"]
        );
    }

    /// One file-backed mapping, so that a process with none had its mappings dropped.
    const MAPPED: &str = "7f0000000000-7f0000001000 r-xp 00000000 08:01 1234 /x/lib.so\n";

    /// The `dev:ino` of the fixture's file `<root>/fs/<comm>`.
    fn id(root: &Path, comm: &str) -> (u64, u64) {
        let m = std::fs::metadata(root.join("fs").join(comm)).unwrap();
        (m.dev(), m.ino())
    }

    /// The runtime keeps the role and the argv the listing pass read: they held then.
    fn assert_listed_role(f: &ProcFacts) {
        let runtime = &f.processes[0];
        assert_eq!(runtime.roles, [ProcessRole::new(RUNTIME_ROLE).unwrap()]);
        assert_eq!(
            runtime.argv,
            Some(vec![
                UntrustedText::new("/x/ollama"),
                UntrustedText::new("serve")
            ])
        );
    }

    /// Code review of PR-4d-2, R-B: an exec of the same path keeps the PID, the start time and
    /// the path, but not the arguments (`ollama serve` re-execs as `ollama version`). What the
    /// second pass read may be another program's: the runtime keeps no identity or mappings. A
    /// descendant's arguments are not read again.
    #[test]
    fn an_exec_of_the_same_path_with_other_arguments_keeps_no_identity_or_mappings() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        std::fs::write(root.join("10/maps"), MAPPED).unwrap();
        let f = run(root, &|| {
            std::fs::write(root.join("10/cmdline"), b"/x/ollama\0version\0").unwrap();
            std::fs::write(root.join("11/cmdline"), b"/x/runner\0--other\0").unwrap();
        });
        assert_eq!(pids(&f), [10, 11]);
        let d = detail(&f, 10);
        assert_eq!(
            d.missing,
            ["cmdline: the runtime's arguments changed, or cannot be read again, since it was listed"]
        );
        assert_eq!(d.exe_id, None);
        assert!(f.processes[0].mappings.is_empty(), "{:?}", f.processes[0]);
        assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
        assert_listed_role(&f);
        let d = detail(&f, 11);
        assert!(d.missing.is_empty(), "{d:?}");
        assert_eq!(d.exe_id, Some(id(root, "runner")));
    }

    /// Code review of PR-4d-2, R-B: the file at the runtime's path replaced, and run again, keeps
    /// the path, but not the executable's identity the listing pass read.
    #[test]
    fn an_exec_of_another_file_at_the_same_path_keeps_no_identity_or_mappings() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        std::fs::write(root.join("10/maps"), MAPPED).unwrap();
        let exe = root.join("fs/ollama");
        let listed = id(root, "ollama");
        let f = run(root, &|| {
            // Written beside it and renamed over it: both exist at once, so their inodes differ.
            let new = root.join("fs/ollama.new");
            std::fs::write(&new, b"new").unwrap();
            std::fs::rename(&new, &exe).unwrap();
        });
        assert_ne!(id(root, "ollama"), listed, "the file was not replaced");
        assert_eq!(std::fs::read_link(root.join("10/exe")).unwrap(), exe);
        assert_eq!(pids(&f), [10, 11]);
        let d = detail(&f, 10);
        assert_eq!(
            d.missing,
            ["exe: the process ran another executable (its path or identity changed) since it was listed or during the reads"]
        );
        assert_eq!(d.exe_id, None);
        assert!(f.processes[0].mappings.is_empty(), "{:?}", f.processes[0]);
        assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
        assert_listed_role(&f);
    }

    /// Code review of PR-4d-2, R-B: the same file run with the same arguments raises no gap. The
    /// runtime keeps its identity and its mappings, read whole; so does its descendant, which has
    /// no identity read at listing and no arguments read again.
    #[test]
    fn the_same_file_with_the_same_arguments_keeps_its_identity_and_mappings() {
        let d = tempfile::TempDir::new().unwrap();
        let root = d.path();
        fixture(root);
        std::fs::write(root.join("10/maps"), MAPPED).unwrap();
        let f = run(root, &|| {});
        assert_eq!(pids(&f), [10, 11]);
        let d = detail(&f, 10);
        assert!(d.missing.is_empty(), "{d:?}");
        assert_eq!(d.exe_id, Some(id(root, "ollama")));
        assert_eq!(f.processes[0].mappings.len(), 1, "{:?}", f.processes[0]);
        assert_eq!(f.processes[0].maps_read, MapsRead::Whole);
        assert_listed_role(&f);
        let d = detail(&f, 11);
        assert!(d.missing.is_empty(), "{d:?}");
        assert_eq!(d.exe_id, Some(id(root, "runner")));
        assert_eq!(f.processes[1].maps_read, MapsRead::Whole);
    }

    /// Code review of PR-4d-2, R-B: the executable's identity changed when the second pass's two
    /// reads of it differ, as read (an error is a reading too), or when the first is not the one
    /// the listing pass read. A listing that read no identity says nothing.
    #[test]
    fn an_exec_is_seen_by_the_executables_identity() {
        type Id = Result<(u64, u64), NotObservable>;
        let (a, b): (Id, Id) = (Ok((1, 2)), Ok((1, 3)));
        let denied: Id = Err(NotObservable::PermissionDenied);
        let gone: Id = Err(NotObservable::NoProcess);
        for (listed, first, again, changed) in [
            // Within the pass.
            (None, a, a, false),
            (None, a, b, true),
            (None, a, denied, true),
            (None, denied, a, true),
            (None, denied, denied, false),
            (None, denied, gone, true),
            // Across the passes.
            (Some(a), a, a, false),
            (Some(a), b, b, true),
            (Some(a), denied, denied, true),
            (Some(a), a, b, true),
            (Some(denied), a, a, false),
        ] {
            assert_eq!(
                identity_changed(listed.as_ref(), &first, &again),
                changed,
                "{listed:?} {first:?} {again:?}"
            );
        }
    }

    /// Code review of PR-4d-2, R-B: the runtime's arguments read again are the ones its role
    /// rests on only when `cmdline` is read whole and parses to exactly them.
    #[test]
    fn the_runtimes_arguments_read_again_are_the_listed_ones_or_a_change() {
        let listed = [b"/x/ollama".to_vec(), b"serve".to_vec()];
        let whole = |bytes: &[u8]| -> Result<Read, Errno> { Ok(Read::Whole(bytes.to_vec())) };
        for (case, again, changed) in [
            ("equal", whole(b"/x/ollama\0serve\0"), false),
            ("different", whole(b"/x/ollama\0version\0"), true),
            ("a prefix", whole(b"/x/ollama\0"), true),
            ("longer", whole(b"/x/ollama\0serve\0--x\0"), true),
            ("empty", whole(b""), true),
            ("over 64 KiB", Ok(Read::OverLimit), true),
            ("refused", Err(Errno::ACCESS), true),
            ("gone", Err(Errno::SRCH), true),
        ] {
            assert_eq!(argv_changed(&listed, again), changed, "{case}");
        }
    }

    /// Review of PR-4d-2: one `read(2)` asks for no more than `limit + 1` bytes in all, and
    /// never for 0 while under it.
    #[test]
    fn a_read_requests_at_most_one_byte_over_the_limit() {
        for (read, limit, want) in [
            (0, 0, 1),
            (0, 1, 2),
            (1, 1, 1),
            (0, 8191, 8192),
            (8191, 8191, 1),
            (0, 8192, 8192),
            (8192, 8192, 1),
            (0, 8193, 8192),
            (8192, 8193, 2),
            (8193, 8193, 1),
            (0, u64::MAX, 8192),
            (8192, u64::MAX, 8192),
        ] {
            assert_eq!(
                request(read, limit, 8192),
                want,
                "read {read}, limit {limit}"
            );
        }
    }

    #[test]
    fn read_up_to_keeps_the_limit_and_says_when_there_is_more() {
        let d = tempfile::TempDir::new().unwrap();
        std::fs::write(d.path().join("f"), b"0123456789").unwrap();
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let dir = rustix::fs::openat(rustix::fs::CWD, d.path(), flags, Mode::empty()).unwrap();
        let read = |limit| read_up_to(dir.as_fd(), "f", limit).unwrap();
        assert_eq!(read(0), (vec![], true));
        assert_eq!(read(1), (b"0".to_vec(), true));
        assert_eq!(read(9), (b"012345678".to_vec(), true));
        assert_eq!(read(10), (b"0123456789".to_vec(), false));
        assert_eq!(read(11), (b"0123456789".to_vec(), false));
    }
}
