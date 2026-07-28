#[cfg(all(test, feature = "server"))]
mod test_utils;
#[cfg(any(
    feature = "server",
    feature = "aws",
    feature = "redis",
    feature = "certificate-acme",
    feature = "metrics-prometheus"
))]
mod utils;

#[cfg(feature = "server")]
pub mod config;
pub mod domain;
pub mod outbound;
#[cfg(feature = "server")]
pub mod server;
/// Composition root: the only place adapters are constructed and injected.
#[cfg(feature = "server")]
pub mod setup;
#[cfg(feature = "server")]
pub mod startup;

#[cfg(feature = "server")]
pub use utils::bits_validation;
#[cfg(any(feature = "server", feature = "certificate-acme"))]
pub use utils::cert_manager;
