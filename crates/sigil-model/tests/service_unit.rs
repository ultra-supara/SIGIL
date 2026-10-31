//! A service unit's root, its instance, and the `ServiceUnit` sources (PR-4d-1), on example 19.

mod common;

use common::*;
use sigil_model::*;

fn valid() -> Session {
    let mut s = service_unit();
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()), "example 19 must be valid");
    s
}

/// Rejected with a `ServiceUnit` error whose reason contains `why`.
fn rejected_for(s: &Session, why: &str) {
    let errors = s.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::ServiceUnit { why: w, .. } if w.contains(why))),
        "{why}: {errors:?}"
    );
}

fn exe(s: &mut Session) -> &mut FileInstance {
    s.instances
        .iter_mut()
        .find(|i| i.id.as_str() == "inst:install/bin/ollama")
        .unwrap()
}

fn unit(s: &mut Session) -> &mut FileInstance {
    s.instances
        .iter_mut()
        .find(|i| i.root.as_str() == SERVICE_UNIT_ROOT)
        .unwrap()
}

fn source(s: &mut Session) -> &mut ConfigRef {
    exe(s)
        .discovered_by
        .iter_mut()
        .find_map(|d| match d {
            DiscoverySource::ServiceUnit { config } => Some(config),
            _ => None,
        })
        .expect("a ServiceUnit source")
}

#[test]
fn example_19_is_valid_and_its_unit_is_an_argument() {
    let mut s = valid();
    assert_eq!(unit(&mut s).discovered_by, vec![DiscoverySource::Argument]);
}

#[test]
fn a_service_unit_root_comes_with_an_install_root() {
    let mut s = valid();
    s.request.roots.retain(|r| r.id.as_str() != INSTALL_ROOT);
    rejected_for(&s, "comes with an install root");
}

#[test]
fn the_service_unit_root_holds_exactly_one_instance() {
    let mut s = valid();
    let mut second = unit(&mut s).clone();
    second.id = id("inst:service-unit/other.service");
    s.instances.push(second);
    rejected_for(&s, "holds 2 instances");
    let mut s = valid();
    s.instances.retain(|i| i.root.as_str() != SERVICE_UNIT_ROOT);
    rejected_for(&s, "holds 0 instances");
}

#[test]
fn a_source_names_the_unit_and_the_unit_was_read() {
    let mut s = valid();
    source(&mut s).file = id("inst:install/bin/ollama");
    rejected_for(&s, "is not the service-unit root's instance");
    let mut s = valid();
    unit(&mut s).content = InstanceContent::NotRead {
        why: NotReadReason::BudgetExceeded,
    };
    rejected_for(&s, "the unit was not read");
}

#[test]
fn the_unit_is_the_argument_read_at_its_root() {
    let mut s = valid();
    unit(&mut s).discovered_by = vec![DiscoverySource::Walk];
    rejected_for(&s, "a unit is discovered by Argument only");
    let mut s = valid();
    unit(&mut s).path = t("/etc/systemd/system/other.service");
    rejected_for(&s, "the unit is not at the service-unit root's path");
}

#[test]
fn a_service_unit_root_has_exactly_one_source() {
    let mut s = valid();
    exe(&mut s)
        .discovered_by
        .retain(|d| *d == DiscoverySource::Walk);
    rejected_for(&s, "0 ServiceUnit sources");
    let mut s = valid();
    let config = source(&mut s).clone();
    exe(&mut s)
        .discovered_by
        .push(DiscoverySource::ServiceUnit { config });
    rejected_for(&s, "2 ServiceUnit sources");
}

#[test]
fn a_source_s_key_is_exec_start_and_its_line_counts_from_one() {
    let mut s = valid();
    source(&mut s).key = t("ExecStop");
    rejected_for(&s, "the key is not ExecStart");
    let mut s = valid();
    source(&mut s).line = 0;
    rejected_for(&s, "lines count from 1");
}

#[test]
fn only_the_install_s_bin_ollama_carries_a_source() {
    let mut s = valid();
    exe(&mut s).path = t("/usr/local/bin/ollama-other");
    rejected_for(&s, "only the install root's bin/ollama");
    let mut s = valid();
    let config = source(&mut s).clone();
    unit(&mut s)
        .discovered_by
        .push(DiscoverySource::ServiceUnit { config });
    rejected_for(&s, "only the install root's bin/ollama");
    let mut s = valid();
    let config = source(&mut s).clone();
    exe(&mut s)
        .discovered_by
        .retain(|d| *d == DiscoverySource::Walk);
    s.request.roots.push(ScanRoot {
        id: id("other"),
        path: t("/usr/local"),
    });
    let mut other = exe(&mut s).clone();
    other.id = id("inst:other/bin/ollama");
    other.root = id("other");
    other
        .discovered_by
        .push(DiscoverySource::ServiceUnit { config });
    s.instances.push(other);
    rejected_for(&s, "only the install root's bin/ollama");
}

#[test]
fn argument_stays_refused_outside_binary_and_service_unit_roots() {
    let mut s = valid();
    exe(&mut s).discovered_by.push(DiscoverySource::Argument);
    let errors = s.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::BinaryInput { why, .. }
            if why.contains("discovered by Argument outside a binary inspection"))),
        "{errors:?}"
    );
}

#[test]
fn found_by_names_the_unit_and_its_line() {
    let md = sigil_model::render::markdown::render_session(&valid());
    let prefix = t("Found by:").markdown_inline();
    let line = md
        .lines()
        .find(|l| l.starts_with(&prefix))
        .expect("a Found by line");
    assert!(line.contains(&t(UNIT_PATH).markdown_inline()), "{line}");
    assert!(line.contains(&t("(line 6)").markdown_inline()), "{line}");
    // Without the source, no such line.
    let mut s = valid();
    exe(&mut s)
        .discovered_by
        .retain(|d| *d == DiscoverySource::Walk);
    let md = sigil_model::render::markdown::render_session(&s);
    assert!(!md.lines().any(|l| l.starts_with(&prefix)), "{md}");
}
