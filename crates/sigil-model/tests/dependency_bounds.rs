//! Contextual bounds must precede copying or inspecting shared legacy text.
use sigil_model::{dependency_path::direct_lookup_path, *};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountLarge;
thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static LARGE: Cell<usize> = const { Cell::new(0) };
}
unsafe impl GlobalAlloc for CountLarge {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= 1_048_576 && ACTIVE.try_with(Cell::get).unwrap_or(false) {
            let _ = LARGE.try_with(|n| n.set(n.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if size >= 1_048_576 && ACTIVE.try_with(Cell::get).unwrap_or(false) {
            let _ = LARGE.try_with(|n| n.set(n.get() + 1));
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOC: CountLarge = CountLarge;
fn fixture() -> Session {
    serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/21-deps-values.json"
    ))
    .unwrap()
}
#[test]
fn oversized_owner_is_rejected_before_parent_allocation() {
    for path in [
        format!("/{}/app", "x".repeat(1_048_576)),
        format!("/usr/local/bin/{}", "x".repeat(1_048_576)),
    ] {
        let mut s = fixture();
        s.validate().unwrap();
        let owner = s
            .relations
            .iter()
            .find_map(|r| match r {
                Relation::Candidate {
                    context: Some(c), ..
                } => Some(c.requester.clone()),
                _ => None,
            })
            .unwrap();
        let file = s.instances.iter_mut().find(|f| f.id == owner).unwrap();
        file.path = path.into();
        file.path_proof = None;
        LARGE.set(0);
        ACTIVE.set(true);
        let result = s.validate();
        ACTIVE.set(false);
        assert_eq!(LARGE.get(), 0, "owner path copied before byte rejection");
        assert!(format!("{:?}", result.unwrap_err()).contains("lookup byte limit"));
        // Old paths are still data when no contextual Candidate uses them.
        s.relations.retain(|r| {
            !matches!(
                r,
                Relation::Candidate {
                    context: Some(_),
                    ..
                }
            )
        });
        s.validate().unwrap();
    }
}
#[test]
fn direct_cwd_byte_limit_precedes_nul_qualification() {
    let mut cwd = vec![b'x'; 1_048_576];
    cwd[0] = b'/';
    *cwd.last_mut().unwrap() = 0;
    assert_eq!(
        direct_lookup_path(b"sub/lib.so", b"/scan/app", Some(&cwd)),
        Err("dependency path: lookup byte limit 65536 exceeded")
    );
    assert_eq!(
        direct_lookup_path(b"/scan/lib.so", b"/scan/app", Some(&cwd)).unwrap(),
        b"/scan/lib.so"
    );
}
#[test]
fn repeated_saved_candidates_reject_shared_oversized_cwd_at_byte_guard() {
    let mut s = fixture();
    let value_index = s
        .values
        .iter()
        .position(|v| matches!(v.key, ValueKey::Cwd) && matches!(v.value, TriValue::Known(_)))
        .unwrap();
    let id = s.values[value_index].id.clone();
    let mut relation = s.relations.iter().find(|r| matches!(r, Relation::Candidate { via: SearchRule::Runpath, context: Some(c), .. } if c.process.is_some())).unwrap().clone();
    if let Relation::Candidate {
        context: Some(c), ..
    } = &mut relation
    {
        c.values.push(id);
    }
    s.relations
        .retain(|r| !matches!(r, Relation::Candidate { .. }));
    for _ in 0..128 {
        s.relations.push(relation.clone());
    }
    if let Relation::Candidate { from, .. } = &relation {
        let binary = s.binaries.iter_mut().find(|b| b.slice == *from).unwrap();
        if let ContainerFacts::Elf(elf) = &mut binary.container {
            elf.runpath = vec!["".into()];
        }
    }
    s.validate().unwrap();
    s.values[value_index].value = TriValue::Known(format!("/{}\0", "x".repeat(1_048_576)).into());
    let errors = format!("{:?}", s.validate().unwrap_err());
    assert!(
        errors.matches("lookup byte limit").count() >= 128,
        "each contextual reference must hit the byte guard: {errors}"
    );
    s.relations
        .retain(|r| !matches!(r, Relation::Candidate { .. }));
    s.validate().unwrap();
}
