//! A fake proc root for observe-mode tests: process directories with `comm`, `cmdline`, `stat`,
//! `exe`, `ns/net`, and `fd/<n>` links, and the `net/tcp{,6}` tables, as the kernel shows them.

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// SIGIL's own network namespace in the fixtures.
pub const OWN_NET_NS: u64 = 4026531840;
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
        fake.process(&Proc {
            pid: 1,
            comm: "systemd",
            argv: &["/sbin/init"],
            exe: Some("/usr/lib/systemd/systemd"),
            ..Proc::default()
        });
        fake
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn pid_dir(&self, pid: u32) -> PathBuf {
        self.path().join(pid.to_string())
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
        let fields: Vec<String> = (3..=21).map(|n| n.to_string()).collect();
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
            symlink(exe, dir.join("exe")).unwrap();
        }
        symlink(format!("net:[{}]", p.net_ns), dir.join("ns/net")).unwrap();
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
                let _ =
                    fs::set_permissions(entry.path().join("fd"), fs::Permissions::from_mode(0o755));
            }
        }
    }
}
