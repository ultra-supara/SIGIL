// Allowed (#145): these tests do not test how SIGIL's own ELF tables read their strings.
#[allow(clippy::disallowed_methods)]
pub fn object_file(bytes: &[u8]) -> object::File<'_> {
    object::File::parse(bytes).unwrap()
}
