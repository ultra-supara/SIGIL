//! Collectors. Every file read goes through [`fs::SafeFs`].

pub(crate) mod binread;
pub mod code_collection;
pub mod fs;
pub mod install;
pub mod named;
pub mod ollama_store;
pub mod service_unit;
