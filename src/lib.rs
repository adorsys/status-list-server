#[cfg(test)]
mod test_utils;
mod utils;

pub mod config;
pub mod domain;
pub mod outbound;
pub mod server;
/// Composition root: the only place adapters are constructed and injected.
pub mod setup;
pub mod startup;

pub use utils::bits_validation;
#[cfg(feature = "acme")]
pub use utils::cert_manager;
