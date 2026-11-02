//! A fake proc root for observe-mode tests: process directories with `comm`, `cmdline`, `stat`,
//! `maps`, `exe`, `ns/{net,mnt}`, and `fd/<n>` links, and the `net/tcp{,6}` tables, as the kernel
//! shows them.

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// SIGIL's own network namespace in the fixtures.
pub const OWN_NET_NS: u64 = 4026531840;
/// SIGIL's own mount namespace in the fixtures.
pub const OWN_MNT_NS: u64 = 4026531841;
pub const BOOT_ID: &str = "00000000-0000-4000-8000-000000000000";

pub struct FakeProc {
    dir: TempDir,
    tcp: Vec<String>,
    tcp6: Vec<String>,
}

/// One process of the fixture.
pub struct Proc<'a> {
    pub pid: u32,
    pub comm: &'a str,
    pub argv: &'a [&'a str],
    /// The `exe` link's target; `None` leaves no `exe` link (as for a process whose exe cannot be
    /// read).
    pub exe: Option<&'a str>,
    pub net_ns: u64,
    pub sockets: &'a [u64],
    pub start_ticks: u64,
    /// Its parent (`stat` field 4).
    pub ppid: u32,
    /// The text of its `maps`.
    pub maps: &'a str,
    pub mnt_ns: u64,
    /// Raw process-namespace path; its target need not exist.
    pub cwd: &'a str,
    pub status: &'a [u8],
    pub environ: &'a [u8],
}

impl Default for Proc<'_> {
    fn default() -> Self {
        Proc {
            pid: 100,
            comm: "sshd",
            argv: &["/usr/sbin/sshd"],
            exe: Some("/usr/sbin/sshd"),
            net_ns: OWN_NET_NS,
            sockets: &[],
            start_ticks: 500,
            ppid: 1,
            maps: "",
            mnt_ns: OWN_MNT_NS,
            cwd: "/work",
            status: b"Name:\tfixture\nUid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\n",
            environ: b"",
        }
    }
}

/// The kernel's text for an address on this host: each 32-bit word's native bytes as a host-order
/// integer.
fn row_address(address: IpAddr) -> String {
    let bytes = match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    bytes
        .chunks(4)
        .map(|w| format!("{:08X}", u32::from_ne_bytes([w[0], w[1], w[2], w[3]])))
        .collect()
}

impl FakeProc {
    /// A proc root with SIGIL's own namespace and PID 1.
    pub fn new() -> FakeProc {
        let fake = FakeProc {
            dir: TempDir::new().unwrap(),
            tcp: vec![],
            tcp6: vec![],
        };
        fs::create_dir_all(fake.path().join("self/ns")).unwrap();
        symlink(
            format!("net:[{OWN_NET_NS}]"),
            fake.path().join("self/ns/net"),
        )
        .unwrap();
        symlink(
            format!("mnt:[{OWN_MNT_NS}]"),
            fake.path().join("self/ns/mnt"),
        )
        .unwrap();
        fake.process(&Proc {
            pid: 1,
            comm: "systemd",
            argv: &["/sbin/init"],
            exe: Some("/usr/lib/systemd/systemd"),
            ppid: 0,
            ..Proc::default()
        });
        fake.write_tables();
        fake
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn pid_dir(&self, pid: u32) -> PathBuf {
        self.path().join(pid.to_string())
    }

    /// Where the fixture keeps the file at the absolute `path`: `<root>/fs<path>`. An `exe`
    /// link points there, so `stat` through it is the fixture's file, never the host's.
    pub fn fs(&self, path: &str) -> PathBuf {
        self.path().join("fs").join(path.trim_start_matches('/'))
    }

    /// Makes `name` in a process's directory unreadable. Returns `false` when the process can
    /// still read it (it runs as root).
    pub fn deny(&self, pid: u32, name: &str) -> bool {
        let path = self.pid_dir(pid).join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&path).is_ok() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            return false;
        }
        true
    }

    pub fn process(&self, p: &Proc) {
        let dir = self.pid_dir(p.pid);
        fs::create_dir_all(dir.join("fd")).unwrap();
        fs::create_dir_all(dir.join("ns")).unwrap();
        fs::write(dir.join("comm"), format!("{}\n", p.comm)).unwrap();
        let mut cmdline = vec![];
        for arg in p.argv {
            cmdline.extend_from_slice(arg.as_bytes());
            cmdline.push(0);
        }
        fs::write(dir.join("cmdline"), cmdline).unwrap();
        let mut fields: Vec<String> = (3..=21).map(|n| n.to_string()).collect();
        fields[1] = p.ppid.to_string();
        fs::write(
            dir.join("stat"),
            format!(
                "{} ({}) {} {} 0 0\n",
                p.pid,
                p.comm,
                fields.join(" "),
                p.start_ticks
            ),
        )
        .unwrap();
        if let Some(exe) = p.exe {
            let target = self.fs(exe);
            if !target.exists() {
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                fs::write(&target, b"").unwrap();
            }
            symlink(&target, dir.join("exe")).unwrap();
        }
        symlink(format!("net:[{}]", p.net_ns), dir.join("ns/net")).unwrap();
        symlink(format!("mnt:[{}]", p.mnt_ns), dir.join("ns/mnt")).unwrap();
        fs::write(dir.join("maps"), p.maps).unwrap();
        symlink(p.cwd, dir.join("cwd")).unwrap();
        fs::write(dir.join("status"), p.status).unwrap();
        fs::write(dir.join("environ"), p.environ).unwrap();
        for (n, inode) in p.sockets.iter().enumerate() {
            symlink(
                format!("socket:[{inode}]"),
                dir.join("fd").join((n + 3).to_string()),
            )
            .unwrap();
        }
        symlink("/dev/null", dir.join("fd/0")).unwrap();
    }

    /// Adds a LISTEN row for `address:port` with socket `inode`.
    pub fn listen(&mut self, address: &str, port: u16, inode: u64) {
        let address: IpAddr = address.parse().unwrap();
        let (table, zero) = match address {
            IpAddr::V4(_) => (&mut self.tcp, "0".repeat(8)),
            IpAddr::V6(_) => (&mut self.tcp6, "0".repeat(32)),
        };
        table.push(format!(
            "{:4}: {}:{:04X} {zero}:0000 0A 00000000:00000000 00:00000000 00000000   999        0 {inode} 1 0000000000000000 100 0 0 10 0",
            table.len(),
            row_address(address),
            port
        ));
        self.write_tables();
    }

    fn write_tables(&self) {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        fs::create_dir_all(self.path().join("net")).unwrap();
        for (name, rows) in [("tcp", &self.tcp), ("tcp6", &self.tcp6)] {
            let mut text = vec![header.to_string()];
            text.extend(rows.iter().cloned());
            fs::write(self.path().join("net").join(name), text.join("\n") + "\n").unwrap();
        }
    }

    /// Makes a process's fd table unreadable, as for another user's process. Returns `false` when
    /// the process can still read it (it runs as root), so the case cannot be observed.
    pub fn deny_fds(&self, pid: u32) -> bool {
        let fd = self.pid_dir(pid).join("fd");
        fs::set_permissions(&fd, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&fd).is_ok() {
            fs::set_permissions(&fd, fs::Permissions::from_mode(0o755)).unwrap();
            return false;
        }
        true
    }

    /// Adds a raw row to `net/tcp`, e.g. one the parser cannot read.
    pub fn raw_tcp(&mut self, row: &str) {
        self.tcp.push(row.to_string());
        self.write_tables();
    }

    /// Makes a process's directory unreadable. Returns `false` when the process can still read it
    /// (it runs as root).
    pub fn deny_dir(&self, pid: u32) -> bool {
        let dir = self.pid_dir(pid);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&dir).is_ok() {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            return false;
        }
        true
    }

    /// Removes PID 1, as under `hidepid`.
    pub fn hide_pid1(&self) {
        fs::remove_dir_all(self.pid_dir(1)).unwrap();
    }
}

impl Drop for FakeProc {
    fn drop(&mut self) {
        // Restore permissions so that the temporary directory can be removed.
        if let Ok(entries) = fs::read_dir(self.path()) {
            for entry in entries.flatten() {
                let open = || fs::Permissions::from_mode(0o755);
                let _ = fs::set_permissions(entry.path(), open());
                let _ = fs::set_permissions(entry.path().join("fd"), open());
            }
        }
    }
}

/// A `maps` line for the file at `path`, with its real device and inode, as the kernel prints
/// them.
pub fn maps_line(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).unwrap();
    let dev = m.dev();
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    format!(
        "7f0000000000-7f0000001000 r-xp 00000000 {major:02x}:{minor:02x} {} {}",
        m.ino(),
        path.display()
    )
}

/// Counts the opens of files (inotify `IN_OPEN`), to pin which files the collector reads and how
/// often. Closes are watched too: inotify merges an event identical to the last one queued, so two
/// opens in a row would count once.
pub struct Opens {
    fd: std::os::fd::OwnedFd,
    watches: Vec<i32>,
}

impl Opens {
    pub fn watch(paths: &[PathBuf]) -> Opens {
        use rustix::fs::inotify;
        let fd =
            inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC).unwrap();
        let watches = paths
            .iter()
            .map(|p| {
                let flags = inotify::WatchFlags::OPEN | inotify::WatchFlags::CLOSE_NOWRITE;
                inotify::add_watch(&fd, p, flags).unwrap()
            })
            .collect();
        Opens { fd, watches }
    }

    /// How often each watched file was opened, in the order given.
    pub fn counts(&self) -> Vec<usize> {
        use rustix::fs::inotify;
        let mut counts = vec![0; self.watches.len()];
        let mut buffer = [std::mem::MaybeUninit::uninit(); 4096];
        let mut reader = inotify::Reader::new(&self.fd, &mut buffer);
        loop {
            match reader.next() {
                Ok(event) => {
                    if event.events().contains(inotify::ReadFlags::OPEN) {
                        if let Some(i) = self.watches.iter().position(|w| *w == event.wd()) {
                            counts[i] += 1;
                        }
                    }
                }
                Err(rustix::io::Errno::AGAIN) => return counts,
                Err(e) => panic!("inotify: {e}"),
            }
        }
    }
}
