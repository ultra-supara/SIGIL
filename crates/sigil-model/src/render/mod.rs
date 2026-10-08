//! Renderers of a session (plan §4.3, §4.10). Pure: no I/O, so they also run in the browser
//! viewer. Every value they show goes through the [`UntrustedText`](crate::text::UntrustedText)
//! escape API.

pub mod markdown;
