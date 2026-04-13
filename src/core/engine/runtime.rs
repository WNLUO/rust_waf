use super::*;

static ENTRY_LISTENER_RUNTIME: OnceLock<Arc<EntryListenerRuntime>> = OnceLock::new();
#[cfg(feature = "http3")]
static HTTP3_LISTENER_RUNTIME: OnceLock<Arc<Http3ListenerRuntime>> = OnceLock::new();

mod engine_impl;
mod listeners;
mod stream;

pub use engine_impl::WafEngine;
#[cfg(feature = "http3")]
use listeners::build_http3_endpoint;
use listeners::EntryListenerRuntime;
#[cfg(feature = "http3")]
use listeners::Http3ListenerRuntime;
pub(crate) use listeners::{
    shutdown_entry_listener_runtime, sync_entry_listener_runtime, validate_entry_listener_config,
};
#[cfg(feature = "http3")]
pub(crate) use listeners::{
    shutdown_http3_listener_runtime, sync_http3_listener_runtime, validate_http3_listener_config,
};
pub(crate) use stream::PrefixedStream;
