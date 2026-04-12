use super::*;

static ENTRY_LISTENER_RUNTIME: OnceLock<Arc<EntryListenerRuntime>> = OnceLock::new();

mod engine_impl;
mod listeners;
mod stream;

pub use engine_impl::WafEngine;
#[cfg(feature = "http3")]
use listeners::build_http3_endpoint;
use listeners::EntryListenerRuntime;
pub(crate) use listeners::{sync_entry_listener_runtime, validate_entry_listener_config};
pub(crate) use stream::PrefixedStream;
