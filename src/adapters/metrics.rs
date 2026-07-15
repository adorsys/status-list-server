//! Metrics collector adapters.
use crate::ports::MetricsCollector;

#[derive(Clone, Default)]
pub struct NoopMetricsCollector;

impl MetricsCollector for NoopMetricsCollector {
    fn increment(&self, _name: &'static str) {}
}
