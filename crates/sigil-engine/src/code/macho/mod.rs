//! Bounded Mach-O code evidence; policy admission remains separately gated.
pub(crate) mod bind;
#[allow(dead_code)]
pub(crate) mod image;
mod record;
mod reloc;
mod stubs;
pub(crate) mod unwind;
use crate::code::{
    reader::{Reader, SliceWindow},
    ArtifactAnalysis, CodeOutcome, Run,
};
use sigil_model::{Arch, MachOFacts, SliceId};
fn read_error(error: image::Error, reader: &Reader<'_>, run: &mut Run) {
    match error {
        image::Error::Read(e) => run.refusal(e, "Mach-O code", reader),
        e => run.gap(format!("code: Mach-O image: {e:?}")),
    }
}
pub(crate) fn analyze(
    analysis: &mut ArtifactAnalysis<'_>,
    slice: SliceId,
    window: SliceWindow,
    arch: Arch,
    facts: &MachOFacts,
    local_gaps: &[String],
    ambiguous: bool,
) -> CodeOutcome {
    let supported = matches!(arch, Arch::Aarch64 | Arch::X86_64)
        && matches!(facts.file_type, 1 | 2 | 6 | 8)
        && facts.is_64
        && facts.little_endian == Some(true)
        && !(arch == Arch::Aarch64 && facts.cpu_subtype as u32 & 0x00ffffff != 0);
    analysis.slice(supported, |reader, run| {
        if ambiguous {
            run.gap("code: Mach-O ambiguous slice architecture".into());
            return (vec![], vec![]);
        }
        for g in local_gaps {
            run.gap(format!("code: Mach-O container: {g}"));
        }
        let mut view = match image::build(
            reader,
            slice,
            window,
            arch,
            Some((facts.cpu_type, facts.cpu_subtype)),
        ) {
            Ok(v) => v,
            Err(e) => {
                read_error(e, reader, run);
                return (vec![], vec![]);
            }
        };
        let name_bytes = facts.imports.iter().try_fold(0u64, |sum, i| {
            let library = match &i.library {
                sigil_model::MachOLibrary::Dylib { name: Some(n), .. } => n.as_bytes().len() as u64,
                _ => 0,
            };
            sum.checked_add(i.name.as_bytes().len() as u64)?
                .checked_add(library)
        });
        if !run.charge(crate::code::Work::References, facts.imports.len() as u64)
            || name_bytes.is_none_or(|n| !run.charge(crate::code::Work::Names, n))
        {
            return (vec![], vec![]);
        }
        view.imports = facts.imports.clone();
        match crate::code::data::signatures() {
            Ok(sig) => record::analyze(&view, sig, reader, run),
            Err(e) => {
                run.gap(format!("code: signatures: {e}"));
                (vec![], vec![])
            }
        }
    })
}
