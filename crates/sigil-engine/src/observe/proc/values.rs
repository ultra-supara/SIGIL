use super::{not_observable, read_limited, request, Ctx, Read, ValueDetail};
use crate::analyze::values::{allowlisted_env, minimize_env, observed_role, value_id, QUERIED_ENV};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use sigil_model::{
    NotObservable, ObsSource, ProcessRef, ProcessRole, ProcessValue, ProcessValueRead, TriValue,
    UnknownReason, UntrustedText, ValueKey, ValueOrigin,
};
use std::collections::BTreeSet;
use std::os::fd::BorrowedFd;

fn unknown(reason: UnknownReason) -> TriValue {
    TriValue::Unknown { reason }
}
fn unobservable(reason: NotObservable) -> TriValue {
    unknown(UnknownReason::NotObservable(reason))
}
// A missing individual proc source is not proof that this ProcessRef exited. Only
// second_image/restat can establish Gone. Keep read failure diagnostics separately.
fn read_failure(entry: &str, error: Errno) -> (NotObservable, String) {
    let reason = match not_observable(error) {
        NotObservable::PermissionDenied => NotObservable::PermissionDenied,
        _ => NotObservable::ReadIncomplete,
    };
    let diagnostic = if reason == NotObservable::PermissionDenied {
        format!("{entry}: cannot be read (PermissionDenied)")
    } else {
        format!("{entry}: cannot be read (ReadIncomplete; source error {error:?})")
    };
    (reason, diagnostic)
}

pub(super) struct ValueBatch {
    pub process: ProcessRef,
    pub values: Vec<ProcessValue>,
    pub missing: Vec<String>,
    role: Option<ProcessRole>,
    /// True when all attempted value reads were refused, or a permission-only process
    /// guard invalidated every requested row. Independent successful reads clear it.
    denied: bool,
    /// Eligibility for permission-only unavailability. Successful reads leave this alone;
    /// any nonpermission failure or output omission clears it, without parsing diagnostics.
    permission_only: bool,
    attempted: bool,
    env_enabled: bool,
    env_slots_complete: bool,
}

impl ValueBatch {
    pub fn new(ctx: &Ctx<'_>, process: ProcessRef, roles: &[ProcessRole]) -> Self {
        let mut out = Self {
            role: observed_role(&process, roles).ok(),
            process,
            values: vec![],
            missing: vec![],
            denied: true,
            permission_only: true,
            attempted: false,
            env_enabled: ctx.observe_env,
            env_slots_complete: true,
        };
        for (key, read) in [
            (ValueKey::Cwd, ProcessValueRead::Cwd),
            (ValueKey::User, ProcessValueRead::EffectiveUid),
            (ValueKey::Group, ProcessValueRead::EffectiveGid),
        ] {
            out.slot(ctx, key, read);
        }
        if ctx.observe_env {
            for name in QUERIED_ENV {
                if out
                    .slot(
                        ctx,
                        ValueKey::Env(UntrustedText::from_bytes(name.to_vec())),
                        ProcessValueRead::InitialEnvironment,
                    )
                    .is_none()
                {
                    out.env_slots_complete = false;
                }
            }
        }
        out
    }

    fn gap(&mut self, why: &str) {
        if !self.missing.iter().any(|m| m == why) {
            self.missing.push(why.to_string());
        }
    }
    fn incomplete(&mut self, why: &str) {
        self.permission_only = false;
        self.denied = false;
        self.gap(why);
    }
    fn slot(&mut self, ctx: &Ctx<'_>, key: ValueKey, read: ProcessValueRead) -> Option<usize> {
        if let Some(i) = self.values.iter().position(|v| v.key == key) {
            return Some(i);
        }
        let left = ctx.values_left.get();
        if left == 0 {
            self.incomplete("process_values exhausted");
            return None;
        }
        // Charge attempts before constructing a record. Failed identities and invalidated
        // observations never refund this output allowance.
        ctx.values_left.set(left - 1);
        let Some(role) = self.role.clone() else {
            self.incomplete("an observation role could not be constructed");
            return None;
        };
        let origin = ValueOrigin::ObservedProcess {
            process: self.process.clone(),
            source: ObsSource::Proc,
            read: Some(read),
        };
        let Ok(id) = value_id(&role, &key, &origin) else {
            self.incomplete("a process value identity could not be constructed");
            return None;
        };
        let i = self.values.len();
        self.values.push(ProcessValue {
            id,
            process_role: role,
            key,
            value: unobservable(NotObservable::ReadIncomplete),
            origin,
            applies_to: vec![],
        });
        Some(i)
    }
    fn set(&mut self, key: &ValueKey, value: TriValue) {
        if let Some(v) = self.values.iter_mut().find(|v| &v.key == key) {
            v.value = value;
        }
    }
    fn env_unknown(&mut self, reason: NotObservable, why: &str) {
        self.permission_only &= reason == NotObservable::PermissionDenied;
        for v in &mut self.values {
            if matches!(v.key, ValueKey::Env(_)) {
                v.value = unobservable(reason);
            }
        }
        self.gap(why);
    }
    pub fn invalidate(&mut self, reason: UnknownReason, why: &str) {
        let permission = matches!(
            &reason,
            UnknownReason::NotObservable(NotObservable::PermissionDenied)
        );
        for v in &mut self.values {
            v.value = unknown(reason.clone());
        }
        // Opening/restatting the process can fail before any individual value read. It is
        // still an attempted observation. Preserve earlier budget/parser/output omissions
        // as Partial; a permission guard alone makes every requested row unconfirmable.
        self.attempted = true;
        self.permission_only &= permission;
        self.denied = self.permission_only;
        self.gap(why);
    }
    pub fn detail(&self) -> ValueDetail {
        ValueDetail {
            process: self.process.clone(),
            denied: self.attempted && self.denied && !self.values.is_empty(),
            missing: self.missing.clone(),
        }
    }
    fn read_error(&mut self, entry: &str, e: Errno) -> (NotObservable, String) {
        let (reason, diagnostic) = read_failure(entry, e);
        self.denied &= reason == NotObservable::PermissionDenied;
        self.permission_only &= reason == NotObservable::PermissionDenied;
        (reason, diagnostic)
    }
    pub fn read(&mut self, ctx: &Ctx<'_>, dir: BorrowedFd<'_>) {
        if self.values.is_empty() {
            return;
        }
        if self.values.iter().any(|v| v.key == ValueKey::Cwd) {
            self.attempted = true;
            // readlinkat_raw avoids the allocating API's unbounded growth. A filled buffer
            // may be truncated and is Unknown; never open or stat the target.
            let mut path = [0u8; 4097];
            match rustix::fs::readlinkat_raw(dir, "cwd", &mut path[..]) {
                Ok(n) if n < path.len() => {
                    self.denied = false;
                    self.set(
                        &ValueKey::Cwd,
                        TriValue::Known(UntrustedText::from_bytes(path[..n].to_vec())),
                    );
                }
                Ok(_) => {
                    let why =
                        "cwd: readlink reached the 4097-byte buffer; the path may be truncated";
                    self.set(&ValueKey::Cwd, unobservable(NotObservable::ReadIncomplete));
                    self.incomplete(why);
                }
                Err(e) => {
                    let (reason, why) = self.read_error("cwd", e);
                    self.set(&ValueKey::Cwd, unobservable(reason));
                    self.gap(&why);
                }
            }
        }
        if self
            .values
            .iter()
            .any(|v| matches!(v.key, ValueKey::User | ValueKey::Group))
        {
            self.attempted = true;
            let fields = match read_limited(dir, "status", ctx.budgets.max_status_bytes) {
                Ok(Read::Whole(bytes)) => {
                    self.denied = false;
                    Ok((effective(&bytes, b"Uid:"), effective(&bytes, b"Gid:")))
                }
                Ok(Read::OverLimit) => {
                    self.incomplete("status: proc_status_bytes exhausted");
                    Err(NotObservable::ReadIncomplete)
                }
                Err(e) => {
                    let (reason, why) = self.read_error("status", e);
                    self.gap(&why);
                    Err(reason)
                }
            };
            for (key, label, value) in [
                (
                    ValueKey::User,
                    "Uid",
                    fields.as_ref().ok().and_then(|x| x.0),
                ),
                (
                    ValueKey::Group,
                    "Gid",
                    fields.as_ref().ok().and_then(|x| x.1),
                ),
            ] {
                match value {
                    Some(n) => self.set(&key, TriValue::Known(UntrustedText::new(n.to_string()))),
                    None => {
                        let why = if fields.is_ok() {
                            format!(
                                "status: {label} is missing, duplicate, or not four decimal IDs"
                            )
                        } else {
                            self.missing
                                .last()
                                .cloned()
                                .unwrap_or_else(|| "status: not read".into())
                        };
                        let reason = fields
                            .as_ref()
                            .err()
                            .copied()
                            .unwrap_or(NotObservable::ReadIncomplete);
                        self.permission_only &= reason == NotObservable::PermissionDenied;
                        self.set(&key, unobservable(reason));
                        self.gap(&why);
                    }
                }
            }
        }
        if self.env_enabled {
            if !self.env_slots_complete {
                self.env_unknown(
                    NotObservable::ReadIncomplete,
                    "environ: process_values exhausted before the queried keys were reserved",
                );
                return;
            }
            self.read_environ(ctx, dir);
        }
    }

    fn read_environ(&mut self, ctx: &Ctx<'_>, dir: BorrowedFd<'_>) {
        if ctx.environ_left.get() == 0 {
            self.denied = false;
            self.env_unknown(
                NotObservable::ReadIncomplete,
                "environ: proc_environ_total_bytes exhausted",
            );
            return;
        }
        self.attempted = true;
        let fd = match rustix::fs::openat(
            dir,
            "environ",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                let (reason, why) = self.read_error("environ", e);
                self.env_unknown(reason, &why);
                return;
            }
        };
        let total = ctx.environ_left.get();
        let limit = ctx.budgets.max_environ_bytes.min(total);
        let mut count = 0usize;
        let mut buffer = [0u8; 8192];
        let mut entry = EnvEntry::default();
        let mut names = BTreeSet::<[u8; 32]>::new();
        let mut present = BTreeSet::<usize>::new();
        let mut malformed = false;
        let outcome: Result<(), (NotObservable, String)> = loop {
            let want = request(count, limit, buffer.len());
            let n = match rustix::io::read(&fd, &mut buffer[..want]) {
                Ok(n) => n,
                Err(Errno::INTR) => continue,
                Err(e) => break Err(self.read_error("environ", e)),
            };
            if n == 0 {
                if entry.started {
                    malformed = true;
                } // unterminated final entry
                break if malformed {
                    Err((
                        NotObservable::ReadIncomplete,
                        "environ: duplicate, malformed, or unterminated entry".into(),
                    ))
                } else {
                    Ok(())
                };
            }
            // The sentinel byte also consumes the global byte allowance; saturating avoids a
            // refund or underflow. No later process can reuse bytes discarded after an exec.
            ctx.environ_left
                .set(ctx.environ_left.get().saturating_sub(n as u64));
            if count as u64 + n as u64 > limit {
                let budget = if total <= ctx.budgets.max_environ_bytes {
                    "proc_environ_total_bytes"
                } else {
                    "proc_environ_bytes"
                };
                break Err((
                    NotObservable::ReadIncomplete,
                    format!("environ: {budget} exhausted"),
                ));
            }
            count += n;
            let mut output_exhausted = false;
            for &byte in &buffer[..n] {
                if byte == 0 {
                    if !entry.started || !entry.equal || !entry.valid_name {
                        malformed = true;
                    }
                    let digest: [u8; 32] = entry.digest.clone().finalize().into();
                    if !names.insert(digest) {
                        malformed = true;
                    }
                    if let Some(i) = entry.slot {
                        self.values[i].value =
                            TriValue::Known(minimize_env(&entry.name, &entry.value));
                        present.insert(i);
                    }
                    entry = EnvEntry::default();
                    continue;
                }
                entry.started = true;
                if !entry.equal {
                    if byte == b'=' {
                        entry.equal = true;
                        entry.valid_name &= entry.name_len > 0;
                        if entry.possible && entry.valid_name && allowlisted_env(&entry.name) {
                            entry.slot = self.slot(
                                ctx,
                                ValueKey::Env(UntrustedText::from_bytes(entry.name.clone())),
                                ProcessValueRead::InitialEnvironment,
                            );
                            if entry.slot.is_none() {
                                output_exhausted = true;
                                break;
                            }
                        }
                    } else {
                        let valid = byte.is_ascii_alphabetic()
                            || byte == b'_'
                            || (entry.name_len > 0 && byte.is_ascii_digit());
                        entry.valid_name &= valid;
                        entry.name_len += 1;
                        entry.digest.update([byte]);
                        if entry.possible {
                            entry.name.push(byte);
                            if !possible_allowlisted_name(&entry.name) {
                                entry.possible = false;
                                entry.name.clear();
                            }
                        }
                    }
                } else if entry.slot.is_some() {
                    entry.value.push(byte);
                }
            }
            if output_exhausted {
                break Err((
                    NotObservable::ReadIncomplete,
                    "environ: process_values exhausted while filtering entries".into(),
                ));
            }
        };
        match outcome {
            Ok(()) => {
                self.denied = false;
                for (i, value) in self.values.iter_mut().enumerate() {
                    if matches!(value.key, ValueKey::Env(_)) && !present.contains(&i) {
                        value.value = TriValue::Absent;
                    }
                }
            }
            Err((reason, why)) => {
                // A tail may contain a later duplicate of any completed name. Neither Known
                // prefixes nor Absent survive an incomplete/malformed/duplicate stream.
                if reason != NotObservable::PermissionDenied {
                    self.denied = false;
                }
                self.env_unknown(reason, &why);
            }
        }
    }
}

struct EnvEntry {
    started: bool,
    equal: bool,
    valid_name: bool,
    possible: bool,
    name_len: usize,
    name: Vec<u8>,
    digest: Sha256,
    slot: Option<usize>,
    value: Vec<u8>,
}
impl Default for EnvEntry {
    fn default() -> Self {
        Self {
            started: false,
            equal: false,
            valid_name: true,
            possible: true,
            name_len: 0,
            name: vec![],
            digest: Sha256::new(),
            slot: None,
            value: vec![],
        }
    }
}
fn possible_allowlisted_name(name: &[u8]) -> bool {
    b"GGML_".starts_with(name)
        || name.starts_with(b"GGML_")
        || QUERIED_ENV.iter().any(|key| key.starts_with(name))
}
fn effective(bytes: &[u8], label: &[u8]) -> Option<u32> {
    let mut found = None;
    for line in bytes.split(|b| *b == b'\n') {
        let Some(tail) = line.strip_prefix(label) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        let mut fields = tail
            .split(u8::is_ascii_whitespace)
            .filter(|f| !f.is_empty());
        let mut ids = [0u32; 4];
        for slot in &mut ids {
            let field = fields.next()?;
            if !field.iter().all(u8::is_ascii_digit) {
                return None;
            }
            *slot = field.iter().try_fold(0u32, |n, b| {
                n.checked_mul(10)?.checked_add(u32::from(*b - b'0'))
            })?;
        }
        if fields.next().is_some() {
            return None;
        }
        found = Some(ids[1]);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercise the real batch constructor/invalidation and coverage projection without
    // depending on mode bits or root privileges. The empty synthetic proc root contains no
    // live process: the ProcessRef/stat-identity guard result is injected at ValueBatch's
    // private boundary, exactly as second() handles Pass::Unreadable.
    fn guard_case(
        reason: NotObservable,
        slots: u64,
        earlier_incomplete: Option<&str>,
    ) -> (Vec<ProcessValue>, ValueDetail, sigil_model::CoverageState) {
        use super::super::{observe_values, ProcBudgets, When};
        use std::cell::Cell;
        use std::os::fd::AsFd;

        let temp = tempfile::TempDir::new().unwrap();
        let root = rustix::fs::openat(
            rustix::fs::CWD,
            temp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let at = sigil_model::Timestamp::new("2026-11-02T00:00:00Z").unwrap();
        let budgets = ProcBudgets {
            max_process_values: slots,
            ..ProcBudgets::default()
        };
        let during = |_, _| {};
        let ctx = Ctx {
            root: root.as_fd(),
            when: When {
                at: &at,
                boot_id: "b",
            },
            budgets,
            own_mnt_ns: None,
            maps_left: Cell::new(budgets.max_maps_total_bytes),
            entries_left: Cell::new(budgets.max_maps_entries),
            during: &during,
            observe_env: false,
            environ_left: Cell::new(budgets.max_environ_total_bytes),
            values_left: Cell::new(budgets.max_process_values),
        };
        let process = ProcessRef {
            pid: 10,
            start_ticks: 100,
            boot_id: "b".into(),
        };
        let roles = [ProcessRole::new(super::super::RUNTIME_ROLE).unwrap()];
        let mut batch = ValueBatch::new(&ctx, process.clone(), &roles);
        if let Some(why) = earlier_incomplete {
            batch.incomplete(why);
        }
        let diagnostic =
            format!("the process cannot be read again ({reason:?}); its values are unknown");
        batch.invalidate(UnknownReason::NotObservable(reason), &diagnostic);
        let detail = batch.detail();
        assert!(detail.missing.contains(&diagnostic));

        let mut facts = observe_values(temp.path(), &at, "b", budgets, false);
        facts.values = batch.values;
        facts.value_details = vec![detail.clone()];
        let entries = crate::analyze::values::observed_coverage(&facts);
        let state = entries
            .iter()
            .find(|entry| entry.scope == sigil_model::Ref::Process(process.clone()))
            .unwrap()
            .state
            .clone();
        (facts.values, detail, state)
    }

    #[test]
    fn process_identity_permission_invalidation_is_typed_unavailable() {
        let (values, detail, state) = guard_case(NotObservable::PermissionDenied, 3, None);
        assert_eq!(values.len(), 3);
        for value in values {
            assert_eq!(
                value.value,
                TriValue::Unknown {
                    reason: UnknownReason::NotObservable(NotObservable::PermissionDenied),
                }
            );
        }
        assert!(detail.denied);
        assert_eq!(
            state,
            sigil_model::CoverageState::Unavailable {
                why: sigil_model::Unavailability::PermissionDenied,
            }
        );
    }

    #[test]
    fn process_identity_read_incomplete_invalidation_stays_partial() {
        let (values, detail, state) = guard_case(NotObservable::ReadIncomplete, 3, None);
        for value in values {
            assert_eq!(
                value.value,
                TriValue::Unknown {
                    reason: UnknownReason::NotObservable(NotObservable::ReadIncomplete),
                }
            );
        }
        assert!(!detail.denied);
        assert!(
            matches!(state, sigil_model::CoverageState::Partial { missing }
            if missing == detail.missing)
        );
    }

    #[test]
    fn permission_invalidation_preserves_read_and_output_incompleteness_as_partial() {
        for (slots, prior, wanted_gap) in [
            (2, None, "process_values exhausted"),
            (
                3,
                Some("status: proc_status_bytes exhausted"),
                "status: proc_status_bytes exhausted",
            ),
        ] {
            let (values, detail, state) = guard_case(NotObservable::PermissionDenied, slots, prior);
            assert_eq!(values.len(), slots as usize);
            for value in values {
                assert_eq!(
                    value.value,
                    TriValue::Unknown {
                        reason: UnknownReason::NotObservable(NotObservable::PermissionDenied),
                    }
                );
            }
            assert!(!detail.denied);
            assert!(detail.missing.iter().any(|gap| gap == wanted_gap));
            assert!(
                matches!(state, sigil_model::CoverageState::Partial { missing }
                if missing == detail.missing)
            );
        }
    }

    #[test]
    fn read_failures_have_typed_reasons_without_parsing_diagnostics() {
        for error in [
            Errno::ACCESS,
            Errno::PERM,
            Errno::NOENT,
            Errno::SRCH,
            Errno::IO,
        ] {
            let (reason, diagnostic) = read_failure("environ", error);
            let expected = if matches!(error, Errno::ACCESS | Errno::PERM) {
                NotObservable::PermissionDenied
            } else {
                NotObservable::ReadIncomplete
            };
            assert_eq!(
                unobservable(reason),
                TriValue::Unknown {
                    reason: UnknownReason::NotObservable(expected),
                }
            );
            // The concrete source/error explanation belongs to coverage, not TriValue.
            let expected_diagnostic = if expected == NotObservable::PermissionDenied {
                "environ: cannot be read (PermissionDenied)".to_string()
            } else {
                format!("environ: cannot be read (ReadIncomplete; source error {error:?})")
            };
            assert_eq!(diagnostic, expected_diagnostic);
        }
    }
    #[test]
    fn status_effective_fields_are_independent_and_decimal() {
        assert_eq!(effective(b"Uid:\t1 0002 3 4\n", b"Uid:"), Some(2));
        for data in [
            b"Uid: 1 2 3\n".as_slice(),
            b"Uid: 1 2 3 4 5\n",
            b"Uid: 1 -2 3 4\n",
            b"Uid: 1 +2 3 4\n",
            b"Uid: 1 2x 3 4\n",
            b"Uid: 1 4294967296 3 4\n",
            b"Uid: 1 2 3 4\nUid: 1 2 3 4\n",
        ] {
            assert_eq!(effective(data, b"Uid:"), None, "{data:?}");
        }
        assert_eq!(
            effective(b"Name: a\nUid: 1 2 3 4\nGid: 5 6 7 8\n", b"Gid:"),
            Some(6)
        );
    }
    #[test]
    fn name_filter_stops_retaining_unrelated_keys_as_soon_as_impossible() {
        assert!(possible_allowlisted_name(b"G"));
        assert!(possible_allowlisted_name(b"GGML_HUGE"));
        assert!(!possible_allowlisted_name(b"API_TOKEN"));
        assert!(!possible_allowlisted_name(b"LD_PRELOAD"));
        assert!(!possible_allowlisted_name(b"OLLAMA_HOST_SECRET"));
    }
}
