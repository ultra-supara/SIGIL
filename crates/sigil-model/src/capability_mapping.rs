//! Immutable projection of capability raw names, features and named Mach-O lookup libraries.
//! Generated from sigil-engine/signatures/capabilities.toml; source SHA-256 identifies the
//! archive. Engine tests compare every entry and the source hash. Add a new archive on change;
//! never reinterpret a saved session with an unknown hash using the latest mapping.
use crate::{KnowledgeKind, Session, UntrustedText, CAPABILITY_TABLE_ID, LIBCXX, LIBSYSTEM};

pub const V1_SHA256: &str = "2620e766e87f4ecc97f2bc24d3cd0e10cb538ca8c0ece532d69afaaf0ac7215c";

pub struct MachOCapabilityMap {
    entries: &'static [(&'static str, &'static str, &'static str)],
}
pub static V1: MachOCapabilityMap = MachOCapabilityMap {
    entries: V1_ENTRIES,
};

/// The source-table digest is the identity, matching engine policy pinning. The session's
/// package version is informational; no fallback or semantic version inference is made.
pub fn archived(sha256: &str) -> Option<&'static MachOCapabilityMap> {
    (sha256 == V1_SHA256).then_some(&V1)
}
pub fn recorded(s: &Session) -> Option<&'static MachOCapabilityMap> {
    let mut tables = s
        .knowledge
        .iter()
        .filter(|k| k.kind == KnowledgeKind::SignatureDb && k.id == CAPABILITY_TABLE_ID);
    let table = tables.next()?;
    if tables.next().is_some() {
        return None;
    }
    archived(table.sha256.as_str())
}
impl MachOCapabilityMap {
    pub fn mapped_library(&self, raw: &UntrustedText, feature: &str) -> Option<&'static str> {
        let key = raw.as_bytes().strip_prefix(b"_")?;
        let index = self
            .entries
            .binary_search_by(|(symbol, _, _)| symbol.as_bytes().cmp(key))
            .ok()?;
        let (_, mapped_feature, library) = self.entries[index];
        (mapped_feature == feature).then_some(library)
    }
    pub fn entries(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        self.entries
    }
}
const V1_ENTRIES: &[(&str, &str, &str)] = &[
    ("_ZNSt10filesystem10remove_allERKNS_4pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem10remove_allERKNS_4pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem10remove_allERKNS_7__cxx114pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem10remove_allERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem11resize_fileERKNS_4pathEm", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem11resize_fileERKNS_4pathEmRSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem11resize_fileERKNS_7__cxx114pathEm", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem11resize_fileERKNS_7__cxx114pathEmRSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem12copy_symlinkERKNS_4pathES2_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem12copy_symlinkERKNS_4pathES2_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem12copy_symlinkERKNS_7__cxx114pathES3_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem12copy_symlinkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem14create_symlinkERKNS_4pathES2_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem14create_symlinkERKNS_4pathES2_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem14create_symlinkERKNS_7__cxx114pathES3_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem14create_symlinkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_4pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_4pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_4pathES2_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_4pathES2_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathES3_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_directoryERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_hard_linkERKNS_4pathES2_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_hard_linkERKNS_4pathES2_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_hard_linkERKNS_7__cxx114pathES3_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem16create_hard_linkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem18create_directoriesERKNS_4pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem18create_directoriesERKNS_4pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem18create_directoriesERKNS_7__cxx114pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem18create_directoriesERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem24create_directory_symlinkERKNS_4pathES2_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem24create_directory_symlinkERKNS_4pathES2_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem24create_directory_symlinkERKNS_7__cxx114pathES3_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem24create_directory_symlinkERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem4copyERKNS_4pathES2_NS_12copy_optionsE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem4copyERKNS_4pathES2_NS_12copy_optionsERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem4copyERKNS_7__cxx114pathES3_NS_12copy_optionsE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem4copyERKNS_7__cxx114pathES3_NS_12copy_optionsERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6removeERKNS_4pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6removeERKNS_4pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6removeERKNS_7__cxx114pathE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6removeERKNS_7__cxx114pathERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6renameERKNS_4pathES2_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6renameERKNS_4pathES2_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6renameERKNS_7__cxx114pathES3_", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem6renameERKNS_7__cxx114pathES3_RSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem9copy_fileERKNS_4pathES2_NS_12copy_optionsE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem9copy_fileERKNS_4pathES2_NS_12copy_optionsERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem9copy_fileERKNS_7__cxx114pathES3_NS_12copy_optionsE", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt10filesystem9copy_fileERKNS_7__cxx114pathES3_NS_12copy_optionsERSt10error_code", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openERKSsSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1ERKSsSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2EPKcSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC2ERKSsSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEE4openEPKcSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEE4openERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEE4openERKSsSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC1EPKcSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC1ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC1ERKSsSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC2EPKcSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC2ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ifstreamIwSt11char_traitsIwEEC2ERKSsSt13_Ios_Openmode", "cxx.file_read", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEE4openERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEE4openERKSsSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1ERKSsSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC2EPKcSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC2ERKNSt7__cxx1112basic_stringIcS1_SaIcEEESt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC2ERKSsSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEE4openEPKcSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEE4openERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEE4openERKSsSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC1EPKcSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC1ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC1ERKSsSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC2EPKcSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC2ERKNSt7__cxx1112basic_stringIcS0_IcESaIcEEESt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt14basic_ofstreamIwSt11char_traitsIwEEC2ERKSsSt13_Ios_Openmode", "cxx.file_write", LIBSYSTEM),
    ("_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEE4openEPKcj", "cxx.file_read", LIBCXX),
    ("_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEE4openERKNS_12basic_stringIcS2_NS_9allocatorIcEEEEj", "cxx.file_read", LIBCXX),
    ("_ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEE4openEPKcj", "cxx.file_write", LIBCXX),
    ("_ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEE4openERKNS_12basic_stringIcS2_NS_9allocatorIcEEEEj", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem11__copy_fileERKNS1_4pathES4_NS1_12copy_optionsEPNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem12__remove_allERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem13__resize_fileERKNS1_4pathEmPNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem14__copy_symlinkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem16__create_symlinkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem18__create_directoryERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem18__create_directoryERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem18__create_hard_linkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem20__create_directoriesERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem26__create_directory_symlinkERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem6__copyERKNS1_4pathES4_NS1_12copy_optionsEPNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("_ZNSt3__14__fs10filesystem8__renameERKNS1_4pathES4_PNS_10error_codeE", "cxx.file_write", LIBCXX),
    ("connect", "posix.network", LIBSYSTEM),
    ("creat", "posix.file_write", LIBSYSTEM),
    ("dlopen", "posix.dynamic_loading", LIBSYSTEM),
    ("dlsym", "posix.dynamic_loading", LIBSYSTEM),
    ("execve", "posix.process_spawn", LIBSYSTEM),
    ("fopen", "posix.file_read", LIBSYSTEM),
    ("fork", "posix.process_spawn", LIBSYSTEM),
    ("fwrite", "posix.file_write", LIBSYSTEM),
    ("getaddrinfo", "posix.network", LIBSYSTEM),
    ("getenv", "posix.environment_access", LIBSYSTEM),
    ("open", "posix.file_read", LIBSYSTEM),
    ("openat", "posix.file_read", LIBSYSTEM),
    ("posix_spawn", "posix.process_spawn", LIBSYSTEM),
    ("pread", "posix.file_read", LIBSYSTEM),
    ("ptrace", "posix.anti_debug", LIBSYSTEM),
    ("putenv", "posix.environment_access", LIBSYSTEM),
    ("pwrite", "posix.file_write", LIBSYSTEM),
    ("read", "posix.file_read", LIBSYSTEM),
    ("recv", "posix.network", LIBSYSTEM),
    ("recvfrom", "posix.network", LIBSYSTEM),
    ("rename", "posix.file_write", LIBSYSTEM),
    ("send", "posix.network", LIBSYSTEM),
    ("sendto", "posix.network", LIBSYSTEM),
    ("setenv", "posix.environment_access", LIBSYSTEM),
    ("socket", "posix.network", LIBSYSTEM),
    ("system", "posix.process_spawn", LIBSYSTEM),
    ("unlink", "posix.file_write", LIBSYSTEM),
    ("write", "posix.file_write", LIBSYSTEM),
];
