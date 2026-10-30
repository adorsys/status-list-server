//! Issuer tiers and the per-tier limits enforced on management requests.

use std::{fmt, num::NonZeroU32, time::Duration};

use serde::{Deserialize, Serialize};

/// The limits tier an issuer belongs to, assigned by the operator in the
/// issuer registry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IssuerTier {
    #[default]
    Standard,
    Sandbox,
}

impl IssuerTier {
    pub fn as_str(self) -> &'static str {
        match self {
            IssuerTier::Standard => "standard",
            IssuerTier::Sandbox => "sandbox",
        }
    }
}

impl fmt::Display for IssuerTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolved limits for one tier. Configuration guarantees each value is
/// non-zero, within its global cap, and no looser than the standard tier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierLimits {
    pub max_lists: u64,
    pub max_status_index: i32,
    pub max_statuses_per_request: usize,
    /// Non-revoked signing keys an issuer may hold.
    pub max_keys: usize,
    pub write_burst_size: NonZeroU32,
    /// One write token is replenished per period, per replica.
    pub write_period: Duration,
    /// Upper bound on an issuer's lifetime; `None` sets no bound.
    pub max_lifetime: Option<Duration>,
}

/// Limits for every tier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tiers {
    pub standard: TierLimits,
    pub sandbox: TierLimits,
}

impl Tiers {
    pub fn get(&self, tier: IssuerTier) -> &TierLimits {
        match tier {
            IssuerTier::Standard => &self.standard,
            IssuerTier::Sandbox => &self.sandbox,
        }
    }
}

/// An issuer's consumption of its tier's quotas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct IssuerUsage {
    pub lists: u64,
    pub lists_limit: u64,
    pub keys: usize,
    pub keys_limit: usize,
}

impl IssuerUsage {
    pub fn new(lists: u64, keys: usize, limits: &TierLimits) -> Self {
        Self {
            lists,
            lists_limit: limits.max_lists,
            keys,
            keys_limit: limits.max_keys,
        }
    }
}
