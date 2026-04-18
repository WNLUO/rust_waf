#[cfg(feature = "http3")]
use super::*;

#[cfg(feature = "http3")]
mod body;
#[cfg(feature = "http3")]
mod connection;
#[cfg(feature = "http3")]
mod decision;
#[cfg(feature = "http3")]
mod feedback;
#[cfg(feature = "http3")]
mod proxy_flow;
#[cfg(feature = "http3")]
mod response;
#[cfg(feature = "http3")]
mod slow_attack;
#[cfg(all(test, feature = "http3"))]
mod tests;

#[cfg(feature = "http3")]
pub(crate) use self::connection::handle_http3_quic_connection;
