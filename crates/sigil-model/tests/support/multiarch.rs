use sigil_model::*;

pub fn named() -> Session {
    let mut s: Session = serde_json::from_str(include_str!(
        "../../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap();
    s.request.code_analysis = Some(CodeAnalysis::MultiarchV1);
    s.request.budgets.remove(BINARY_SCAN_BYTES);
    s.request.budgets.insert(BINARY_CODE_BYTES.into(), 10);
    s.request
        .required_checks
        .retain(|c| c.as_str() != BINARY_IDENTITY);
    s.coverage.retain(|c| c.check.as_str() != BINARY_IDENTITY);
    s.knowledge.push(code_abi::V1.knowledge().unwrap());
    s.code.clear();
    s.hints.clear();
    s.artifacts[0].code_slice_inventory = Some(CodeSliceInventory::Complete);
    if let ContainerFacts::Elf(e) = &mut s.binaries[0].container {
        e.abi = Some(ElfAbi {
            is_64: true,
            little_endian: true,
            machine: 62,
        });
    }
    let mut child = s
        .coverage
        .iter()
        .find(|c| c.check.as_str() == BINARY_CODE)
        .unwrap()
        .clone();
    child.scope = Ref::Slice(s.artifacts[0].slices[0].id.clone());
    child.budget = Some(budget(4));
    s.coverage.push(child);
    parent(&mut s, CoverageState::Complete, Some(4));
    s
}

pub fn budget(used: u64) -> BudgetUse {
    BudgetUse {
        budget: BINARY_CODE_BYTES.into(),
        used,
        limit: 10,
    }
}

pub fn parent(s: &mut Session, state: CoverageState, used: Option<u64>) {
    for c in &mut s.coverage {
        if c.check.as_str() == BINARY_CODE && matches!(c.scope, Ref::Instance(_)) {
            c.state = state.clone();
            c.budget = used.map(budget);
        }
    }
    completeness(s);
}

pub fn completeness(s: &mut Session) {
    let missing: Vec<_> = s
        .request
        .required_checks
        .iter()
        .filter(|check| {
            !s.coverage.iter().any(|c| &c.check == *check)
                || s.coverage
                    .iter()
                    .any(|c| &c.check == *check && !c.state.can_close())
        })
        .cloned()
        .collect();
    s.outcome.completeness = if missing.is_empty() {
        Completeness::Complete
    } else {
        Completeness::Incomplete {
            missing_required: missing,
            gaps: vec![],
        }
    };
}

pub fn fat() -> Session {
    let mut s = named();
    s.artifacts[0].format = Format::MachOFat;
    let mut second = s.artifacts[0].slices[0].clone();
    s.artifacts[0].size = 4096;
    s.artifacts[0].slices[0].size = 1024;
    second.arch = Arch::Aarch64;
    second.offset = 2048;
    second.size = 1024;
    second.id = SliceId::new(format!("{}#aarch64@2048", s.artifacts[0].id)).unwrap();
    s.artifacts[0].slices.push(second);
    let mut binary = s.binaries[0].clone();
    binary.slice = s.artifacts[0].slices[1].id.clone();
    s.binaries.push(binary);
    for (i, b) in s.binaries.iter_mut().enumerate() {
        let cpu = if i == 0 { 0x0100_0007 } else { 0x0100_000c };
        let subtype = if i == 0 { 3 } else { 0 };
        b.container = ContainerFacts::MachO(MachOFacts {
            little_endian: Some(true),
            is_64: true,
            cpu_type: cpu,
            cpu_subtype: subtype,
            fat_cpu_type: Some(cpu),
            fat_cpu_subtype: Some(subtype),
            fat_alignment: Some(0),
            file_type: 2,
            flags: 0,
            uuid: None,
            id_dylib: None,
            load_dylibs: vec![],
            rpaths: vec![],
            dylinker: None,
            imports: vec![],
        });
    }
    s.relations.clear();
    s.coverage.push(Coverage {
        check: CheckId::new(BINARY_CODE).unwrap(),
        scope: Ref::Slice(s.artifacts[0].slices[1].id.clone()),
        state: CoverageState::Complete,
        budget: Some(budget(5)),
    });
    parent(&mut s, CoverageState::Complete, Some(9));
    s
}

pub fn child(s: &mut Session, n: usize) -> &mut Coverage {
    let scope = Ref::Slice(s.artifacts[0].slices[n].id.clone());
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CODE && c.scope == scope)
        .unwrap()
}

pub fn incomplete(s: &Session, indices: &[usize], inventory: bool) -> CoverageState {
    let mut missing: Vec<_> = indices
        .iter()
        .map(|n| format!("code: incomplete slice {}", s.artifacts[0].slices[*n].id))
        .collect();
    if inventory {
        missing.push("code: slice inventory incomplete".into());
    }
    missing.sort();
    CoverageState::Partial { missing }
}

pub fn inventory_partial(s: &mut Session) {
    s.artifacts[0].code_slice_inventory = Some(CodeSliceInventory::Partial {
        missing: vec![
            "code: slice inventory incomplete".into(),
            "fat: invalid descriptor".into(),
        ],
    });
}

pub fn installation(mut s: Session) -> Session {
    let root = RootId::new(INSTALL_ROOT).unwrap();
    s.request.roots[0].id = root.clone();
    s.request.roots[0].path = UntrustedText::new("/installation");
    s.request.audit = vec![AuditScope::new("installation_code").unwrap()];
    s.request.required_checks = vec![CheckId::new(ARTIFACTS_CODE).unwrap()];
    s.instances[0].root = root.clone();
    s.instances[0].discovered_by = vec![DiscoverySource::Walk];
    s.instances[0].id = InstanceId::new("inst:install/bin/ollama").unwrap();
    s.instances[0].path = UntrustedText::new("/installation/bin/ollama");
    s.coverage.retain(|c| c.check.as_str() == BINARY_CODE);
    for c in &mut s.coverage {
        c.check = CheckId::new(ARTIFACTS_CODE).unwrap();
        if matches!(c.scope, Ref::Instance(_)) {
            c.scope = Ref::Artifact(s.artifacts[0].id.clone());
        }
    }
    let incomplete = s.coverage.iter().any(|c| !c.state.can_close());
    s.coverage.push(Coverage {
        check: CheckId::new(ARTIFACTS_CODE).unwrap(),
        scope: Ref::Root(root.clone()),
        state: if incomplete {
            CoverageState::Partial {
                missing: vec!["one or more binary contents have incomplete code coverage".into()],
            }
        } else {
            CoverageState::Complete
        },
        budget: None,
    });
    s.coverage.push(Coverage {
        check: CheckId::new(ARTIFACTS_DISCOVERY).unwrap(),
        scope: Ref::Root(root),
        state: CoverageState::Complete,
        budget: None,
    });
    completeness(&mut s);
    s
}

pub fn matrix() -> Vec<Session> {
    let mut result = Vec::new();
    for case in 0..8 {
        let mut s = fat();
        match case {
            0 => {}
            1 | 2 => {
                let c = child(&mut s, 1);
                c.state = if case == 1 {
                    CoverageState::Unsupported {
                        what: "code: unsupported CPU subtype".into(),
                    }
                } else {
                    CoverageState::Partial {
                        missing: vec!["code: artifact budget exhausted before slice".into()],
                    }
                };
                c.budget = if case == 1 { None } else { Some(budget(0)) };
                let state = incomplete(&s, &[1], false);
                parent(&mut s, state, Some(4));
            }
            3 | 4 => {
                for n in 0..2 {
                    let c = child(&mut s, n);
                    c.state = CoverageState::Unsupported {
                        what: "code: unsupported CPU subtype".into(),
                    };
                    c.budget = None;
                }
                if case == 3 {
                    parent(
                        &mut s,
                        CoverageState::Unsupported {
                            what: "code: no supported slice".into(),
                        },
                        None,
                    );
                } else {
                    inventory_partial(&mut s);
                    let state = incomplete(&s, &[0, 1], true);
                    parent(&mut s, state, Some(0));
                }
            }
            5 => {
                s.binaries.pop();
                let c = child(&mut s, 1);
                c.state = CoverageState::Partial {
                    missing: vec!["code: slice not parsed".into()],
                };
                c.budget = Some(budget(0));
                let state = incomplete(&s, &[1], false);
                parent(&mut s, state, Some(4));
            }
            6 | 7 => {
                inventory_partial(&mut s);
                let count = if case == 6 { 1 } else { 0 };
                s.artifacts[0].slices.truncate(count);
                s.binaries.truncate(count);
                s.coverage.retain(|c| !matches!(&c.scope, Ref::Slice(id) if !s.artifacts[0].slices.iter().any(|x| &x.id == id)));
                let state = incomplete(&s, &[], true);
                parent(&mut s, state, Some(if case == 6 { 4 } else { 0 }));
            }
            _ => unreachable!(),
        }
        // Container diagnostics stay independent of code inventory.
        let state = expected_binary_container(&s, &s.instances[0])
            .unwrap()
            .into_state(0);
        s.coverage
            .iter_mut()
            .find(|c| c.check.as_str() == BINARY_CONTAINER)
            .unwrap()
            .state = state;
        completeness(&mut s);
        result.push(s);
    }
    result
}
