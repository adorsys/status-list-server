#[cfg(any(feature = "server", feature = "postgres"))]
mod database;
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

pub mod adapters;
pub mod application;
#[cfg(feature = "server")]
pub mod config;
pub mod domain;
#[cfg(any(feature = "server", feature = "postgres"))]
pub mod models;
pub mod ports;
#[cfg(feature = "server")]
pub mod startup;
#[cfg(feature = "server")]
pub mod web;

#[cfg(any(feature = "server", feature = "certificate-acme"))]
pub use utils::cert_manager;
#[cfg(feature = "server")]
pub use utils::{bits_validation, state};
