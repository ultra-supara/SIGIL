//! Collectors. Every file read goes through [`fs::SafeFs`].

pub(crate) mod binread;
pub mod fs;
pub mod install;
pub mod ollama_store;
