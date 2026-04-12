use super::*;

static ENTRY_LISTENER_RUNTIME: OnceLock<Arc<EntryListenerRuntime>> = OnceLock::new();

mod engine_impl;
mod listeners;
mod stream;

pub use engine_impl::WafEngine;
pub(crate) use listeners::{sync_entry_listener_runtime, validate_entry_listener_config};
use listeners::EntryListenerRuntime;
#[cfg(feature = "http3")]
use listeners::build_http3_endpoint;
pub(crate) use stream::PrefixedStream;
