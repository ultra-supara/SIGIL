//! The run's own facts (plan §4.2 "Recorded"): who ran SIGIL and on what kernel, and, in observe
//! mode only, the boot it observed.

use std::fs;

use sigil_engine::observe::host::meta;
use sigil_model::{Mode, Timestamp};

mod common;
use common::proc::*;

const BOOT: &str = "5d2c1a40-9b7e-4c1f-8a3d-2e6f0b9c7d11";

fn at() -> Timestamp {
    Timestamp::new("2026-10-08T00:00:00Z").unwrap()
}

fn with_boot_id(fake: &FakeProc, text: &str) {
    let dir = fake.path().join("sys/kernel/random");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("boot_id"), text).unwrap();
}

#[test]
fn observe_mode_records_the_boot() {
    let fake = FakeProc::new();
    with_boot_id(&fake, &format!("{BOOT}\n"));
    let m = meta(Mode::Observe, fake.path(), at());
    assert_eq!(m.boot_id, BOOT);
    assert_eq!((m.started_at.clone(), m.finished_at.clone()), (at(), at()));
    assert_eq!((m.net_ns, m.mnt_ns), (None, None));
}

#[test]
fn static_mode_reads_nothing_under_the_proc_root() {
    let fake = FakeProc::new();
    with_boot_id(&fake, BOOT);
    assert_eq!(meta(Mode::Static, fake.path(), at()).boot_id, "");
}

#[test]
fn a_boot_id_not_in_uuid_form_is_not_recorded() {
    for bad in [
        "",
        "not-a-uuid",
        "5D2C1A40-9B7E-4C1F-8A3D-2E6F0B9C7D11",
        "5d2c1a40-9b7e-4c1f-8a3d-2e6f0b9c7d1",
        "5d2c1a40-9b7e-4c1f-8a3d-2e6f0b9c7d11x",
        "5d2c1a40x9b7e-4c1f-8a3d-2e6f0b9c7d11",
    ] {
        let fake = FakeProc::new();
        with_boot_id(&fake, bad);
        assert_eq!(
            meta(Mode::Observe, fake.path(), at()).boot_id,
            "",
            "{bad:?}"
        );
    }
    // None at all.
    let fake = FakeProc::new();
    assert_eq!(meta(Mode::Observe, fake.path(), at()).boot_id, "");
}

#[test]
fn the_user_and_kernel_are_those_of_this_process() {
    let fake = FakeProc::new();
    let m = meta(Mode::Static, fake.path(), at());
    assert_eq!(m.uid, rustix::process::getuid().as_raw());
    assert_eq!(m.gid, rustix::process::getgid().as_raw());
    assert!(!m.kernel.is_empty());
    assert!(
        m.capabilities.iter().all(|c| c.starts_with("CAP_")),
        "{:?}",
        m.capabilities
    );
    // An unprivileged test run has no effective capabilities; root has many.
    assert_eq!(
        m.capabilities.is_empty(),
        m.uid != 0,
        "{:?}",
        m.capabilities
    );
}
