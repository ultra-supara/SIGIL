//! Go build info (spec §4.5). Filled in by Task 8.

use object::read::elf::FileHeader;
use object::read::ReadCacheOps;
use object::Endianness;
use sigil_model::GoBuildInfo;

use super::elf::Elf;

pub(crate) fn find<R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    _e: &mut Elf<'_, R, H>,
    _section: Option<(u64, u64, u64)>,
) -> Option<GoBuildInfo> {
    None
}
