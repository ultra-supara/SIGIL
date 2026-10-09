//! Known data symbols (spec §4.4). Filled in by Task 7.

use object::read::elf::{FileHeader, SymbolTable};
use object::read::ReadCacheOps;
use object::Endianness;
use sigil_model::DataSymbol;

use super::elf::{Dynamic, Elf};
use super::read::Bounded;

pub(crate) fn read<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    _e: &mut Elf<'d, R, H>,
    _symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    _dynamic: &Dynamic,
) -> Vec<DataSymbol> {
    vec![]
}
