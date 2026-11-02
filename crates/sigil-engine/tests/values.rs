use sigil_engine::analyze::values::{
    allowlisted_env, minimize_env, observed_role, value_id, QUERIED_ENV,
};
use sigil_model::*;

fn process() -> ProcessRef {
    ProcessRef {
        pid: 42,
        start_ticks: 100,
        boot_id: "boot-a".to_string(),
    }
}

#[test]
fn one_allowlist_is_shared_by_configuration_and_observation() {
    for name in QUERIED_ENV {
        assert!(allowlisted_env(name));
    }
    assert_eq!(QUERIED_ENV.len(), 9);
    for name in [b"GGML_ANY_BACKEND_OPTION".as_slice(), b"GGML_X"] {
        assert!(allowlisted_env(name));
    }
    for name in [
        b"PATH".as_slice(),
        b"HOME",
        b"LD_PRELOAD",
        b"AWS_SECRET_ACCESS_KEY",
        b"GGML-X",
        b"GGML_X\0",
        b"GGML_X=bad",
        b"GGML_\xff",
    ] {
        assert!(!allowlisted_env(name), "{name:?}");
    }
}

#[test]
fn role_and_value_ids_include_the_complete_process_and_origin() {
    let p = process();
    let runtime = ProcessRole::new(RUNTIME_ROLE).unwrap();
    assert_eq!(observed_role(&p, &[runtime.clone()]).unwrap(), runtime);
    let anonymous = observed_role(&p, &[]).unwrap();
    assert!(anonymous.as_str().starts_with("observed:"));
    assert_eq!(anonymous.as_str().len(), 9 + 64);
    assert_eq!(anonymous, observed_role(&p, &[]).unwrap());
    let mut pid = p.clone();
    pid.pid += 1;
    let mut start = p.clone();
    start.start_ticks += 1;
    let mut boot = p.clone();
    boot.boot_id.push('b');
    for other in [&pid, &start, &boot] {
        assert_ne!(anonymous, observed_role(other, &[]).unwrap());
    }
    let origin = |p: &ProcessRef| ValueOrigin::ObservedProcess {
        process: p.clone(),
        source: ObsSource::Proc,
        read: Some(ProcessValueRead::Cwd),
    };
    let id = value_id(&anonymous, &ValueKey::Cwd, &origin(&p)).unwrap();
    assert!(id.as_str().starts_with("value:"));
    assert_eq!(id.as_str().len(), 6 + 64);
    assert_eq!(
        id,
        value_id(&anonymous, &ValueKey::Cwd, &origin(&p)).unwrap()
    );
    assert_ne!(id, value_id(&runtime, &ValueKey::Cwd, &origin(&p)).unwrap());
    assert_ne!(
        id,
        value_id(&anonymous, &ValueKey::User, &origin(&p)).unwrap()
    );
    for other in [&pid, &start, &boot] {
        assert_ne!(
            id,
            value_id(&anonymous, &ValueKey::Cwd, &origin(other)).unwrap()
        );
    }
    let configured = |line| ValueOrigin::Configured {
        file: ConfigRef {
            file: InstanceId::new("inst:service-unit/unit.service").unwrap(),
            key: UntrustedText::new("User"),
            line,
        },
        directive: UntrustedText::new("User"),
    };
    assert_ne!(
        value_id(&runtime, &ValueKey::User, &configured(3)).unwrap(),
        value_id(&runtime, &ValueKey::User, &configured(4)).unwrap()
    );
}

#[test]
fn only_ollama_host_has_url_credentials_query_and_fragment_minimized() {
    for (input, expected) in [
        (
            "https://user:secret@host:443/path?token=secret#frag",
            "https://host:443/path",
        ),
        ("http://user@host:11434", "http://host:11434"),
        ("user:secret@host:11434/path?secret=1", "host:11434/path"),
        ("http://[::1]:11434/path#secret", "http://[::1]:11434/path"),
        ("host:11434?secret=1", "host:11434"),
        ("http://host/path@legitimate", "http://host/path@legitimate"),
        ("http://user:a@b@host/path", "http://host/path"),
        ("", ""),
    ] {
        assert_eq!(
            minimize_env(b"OLLAMA_HOST", input.as_bytes()).as_bytes(),
            expected.as_bytes()
        );
    }
    let path = b"/models/alice@host?version=1#part";
    assert_eq!(minimize_env(b"OLLAMA_MODELS", path).as_bytes(), path);
    assert_eq!(
        minimize_env(b"GGML_BACKEND_PATH", b"/a/\xff").as_bytes(),
        b"/a/\xff"
    );
}

#[test]
fn scheme_less_host_userinfo_is_removed_before_a_scheme_like_path() {
    let minimized = minimize_env(
        b"OLLAMA_HOST",
        b"user:CANARY_PASS@host:11434/path://segment/path@legitimate?CANARY_QUERY#CANARY_FRAGMENT",
    );
    assert_eq!(
        minimized.as_bytes(),
        b"host:11434/path://segment/path@legitimate"
    );
}

#[test]
fn network_path_host_userinfo_is_removed_without_changing_actual_path_at_signs() {
    let minimized = minimize_env(
        b"OLLAMA_HOST",
        b"//user:CANARY_PASS@host:11434/path://segment/path@legitimate",
    );
    assert_eq!(
        minimized.as_bytes(),
        b"//host:11434/path://segment/path@legitimate"
    );
    for input in [
        b"host:11434/path://segment/path@legitimate".as_slice(),
        b"//host:11434/path://segment/path@legitimate",
        b"https://host:11434/path://segment/path@legitimate",
        b"/path://segment/path@legitimate",
    ] {
        assert_eq!(minimize_env(b"OLLAMA_HOST", input).as_bytes(), input);
        assert_eq!(minimize_env(b"OLLAMA_MODELS", input).as_bytes(), input);
    }
}
