use serde::Serialize;

mod core;
mod events;
mod metrics;
mod rules;
mod sites_and_safeline;

pub(crate) use self::core::*;
pub(crate) use self::events::*;
pub(crate) use self::metrics::*;
pub(crate) use self::rules::*;
pub(crate) use self::sites_and_safeline::*;

#[derive(Debug, Serialize)]
pub(super) struct ErrorResponse {
    pub(super) error: String,
}
