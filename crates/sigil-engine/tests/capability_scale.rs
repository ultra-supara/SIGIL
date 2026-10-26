//! How capability evaluation scales with the number of slices (#51, PR review): a benchmark, not a
//! check. Run with `cargo test -p sigil-engine --release --test capability_scale -- --ignored
//! --nocapture`: it prints the time of `evaluate`, `validate`, and `policy::verify` on sessions of
//! 500 to 4,000 slices, each one example 16's object under its own name (one `connect` import,
//! called once).

use std::path::Path;
use std::time::Instant;

use sigil_engine::policy::{evaluate, verify, Policy};
use sigil_model::*;

/// Example 16 with its one slice repeated `n` times, each under another artifact: its binary
/// facts, hint, code facts, input, and coverage.
fn many(n: usize) -> Session {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/examples/session-v1/16-binary-code.json");
    let one: Session = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut s = one.clone();
    (
        s.artifacts,
        s.instances,
        s.binaries,
        s.hints,
        s.code,
        s.coverage,
    ) = (vec![], vec![], vec![], vec![], vec![], vec![]);
    let mut roots = vec![];
    for i in 0..n {
        let artifact = ArtifactId::new(format!("sha256:{i:064x}")).unwrap();
        let slice = SliceId::from_parts(&artifact, Arch::X86_64, 0);
        let root = RootId::new(format!("binary-{}", i + 1)).unwrap();
        let instance = InstanceId::new(format!("inst:{root}/f{i}")).unwrap();
        let mut scan_root = one.request.roots[0].clone();
        scan_root.id = root.clone();
        scan_root.path = UntrustedText::new(format!("/home/user/src/f{i}"));
        roots.push(scan_root);
        let mut a = one.artifacts[0].clone();
        a.id = artifact.clone();
        for sl in &mut a.slices {
            sl.id = slice.clone();
        }
        s.artifacts.push(a);
        let mut inst = one.instances[0].clone();
        inst.id = instance.clone();
        inst.root = root;
        inst.path = UntrustedText::new(format!("/home/user/src/f{i}"));
        inst.content = InstanceContent::Read {
            artifact: artifact.clone(),
        };
        s.instances.push(inst);
        let mut b = one.binaries[0].clone();
        b.slice = slice.clone();
        s.binaries.push(b);
        for h in &one.hints {
            let mut h = h.clone();
            h.subject = slice.clone();
            s.hints.push(h);
        }
        let mut c = one.code[0].clone();
        c.slice = slice.clone();
        s.code.push(c);
        for cov in &one.coverage {
            let mut cov = cov.clone();
            cov.scope = Ref::Instance(instance.clone());
            s.coverage.push(cov);
        }
    }
    s.request.roots = roots;
    s
}

#[test]
#[ignore = "a benchmark: run it with --ignored --nocapture"]
fn capability_evaluation_scales_with_the_slices() {
    let mut p = Policy::load(
        "schema = \"sigil-policy/1\"\nname = \"bench\"\n[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"r\"\n",
    )
    .unwrap();
    for n in [500, 1000, 2000, 4000] {
        let mut s = many(n);
        p.binary_audit = s.request.audit.clone();
        let time = s.outcome.policy_time.clone();
        let t = Instant::now();
        evaluate(&mut s, &p, time).unwrap();
        let evaluated = t.elapsed();
        assert_eq!(s.policy_violations.len(), n);
        let t = Instant::now();
        let errors = s.validate().err().unwrap_or_default();
        if let Some(e) = errors.first() {
            println!("  first error: {e}");
        }
        let valid = errors.len();
        let validated = t.elapsed();
        let t = Instant::now();
        let verified = verify(&s, &p).is_ok();
        let verifying = t.elapsed();
        println!(
            "{n:>5} slices: evaluate {evaluated:>10.2?}, validate {validated:>10.2?} \
             ({valid} errors), verify {verifying:>10.2?} ({verified})"
        );
    }
}
