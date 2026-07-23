#[cfg(all(test, feature = "server"))]
mod test_utils;
mod utils;

pub mod adapters;
pub mod application;
#[cfg(feature = "server")]
pub mod config;
pub mod domain;
pub mod ports;
#[cfg(feature = "server")]
pub mod startup;
/// Composition root: the only place adapters are constructed and injected.
#[cfg(feature = "server")]
pub mod state;
#[cfg(feature = "server")]
pub mod web;

#[cfg(feature = "server")]
pub use utils::bits_validation;
#[cfg(any(feature = "server", feature = "certificate-acme"))]
pub use utils::cert_manager;
#[cfg(feature = "server")]
pub use utils::telemetry;
