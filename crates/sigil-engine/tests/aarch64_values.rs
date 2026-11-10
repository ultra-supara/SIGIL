//! Public producer/verifier boundary tests. Private transfer/CFG tests live beside value.rs,
//! so they exercise the actual artifact Run and Reader without exposing a public analysis API.
#[allow(dead_code)]
#[path = "../../sigil-model/tests/support/multiarch.rs"]
mod support;
use sha2::{Digest, Sha256};
use sigil_model::{
    code_abi::{self, CodeAbi, V1},
    *,
};

#[test]
fn signature_knowledge_is_archived() {
    assert_eq!(
        Sha256::digest(code_abi::V1_BYTES.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        code_abi::V1_SHA256
    );
    let original = support::named();
    original.validate().unwrap();
    for case in 0..4 {
        let mut s = original.clone();
        let at = s
            .knowledge
            .iter()
            .position(|k| k.id == code_abi::ID)
            .unwrap();
        match case {
            0 => s.knowledge[at].sha256 = Sha256Hex::new("00".repeat(32)).unwrap(),
            1 => s.knowledge[at].version = "2".into(),
            2 => s.knowledge.push(s.knowledge[at].clone()),
            _ => {
                s.knowledge.remove(at);
            }
        }
        assert!(s.validate().is_err());
    }
    assert!(code_abi::archived("2", code_abi::V1_SHA256).is_none());
    let archived = code_abi::archived("1", code_abi::V1_SHA256).unwrap();
    assert_eq!(archived.knowledge().unwrap(), V1.knowledge().unwrap());
    // Current registry contains v1 only: no fictional future table is installed by this test.
    original.validate().unwrap();
}

#[test]
fn argument_prefix_is_honest() {
    let library = MachOLibrary::Dylib {
        ordinal: 1,
        name: Some(UntrustedText::new(LIBSYSTEM)),
    };
    let plan = V1.argument_plan(
        Some(CodeAbi::DarwinArm64),
        &UntrustedText::new("_open"),
        Some(&library),
    );
    assert_eq!(plan.registers, [Reg::X0, Reg::X1]);
    assert!(matches!(plan.layout, ArgumentLayout::Partial { .. }));
    assert!(plan
        .coverage_gap(&CallId::new("cs:0x1000").unwrap())
        .unwrap()
        .contains("cs:0x1000"));
    let fixed = V1.argument_plan(
        Some(CodeAbi::DarwinArm64),
        &UntrustedText::new("_connect"),
        Some(&library),
    );
    assert_eq!(fixed.registers, [Reg::X0, Reg::X1, Reg::X2]);
    assert_eq!(fixed.layout, ArgumentLayout::Complete);
}

#[test]
fn variadic_and_aggregate_are_not_guessed() {
    for (name, regs) in [
        ("open", &[Reg::X0, Reg::X1][..]),
        ("openat", &[Reg::X0, Reg::X1, Reg::X2][..]),
        ("printf", &[][..]),
        ("_ZN1A3runEv", &[][..]),
    ] {
        let plan = V1.argument_plan(Some(CodeAbi::ElfAarch64), &UntrustedText::new(name), None);
        assert_eq!(plan.registers, regs);
        assert!(matches!(plan.layout, ArgumentLayout::Partial { .. }));
    }
    for library in [
        None,
        Some(MachOLibrary::FlatLookup),
        Some(MachOLibrary::Dylib {
            ordinal: 1,
            name: Some(UntrustedText::new("/tmp/libOther.dylib")),
        }),
    ] {
        let plan = V1.argument_plan(
            Some(CodeAbi::DarwinArm64),
            &UntrustedText::new("_connect"),
            library.as_ref(),
        );
        assert!(plan.registers.is_empty());
        assert!(matches!(plan.layout, ArgumentLayout::Partial { .. }));
    }
}
