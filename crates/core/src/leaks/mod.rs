//! Credential and domain leak monitor.
//!
//! Watches configured domains and VIP addresses for breaches that a
//! read-only source (HIBP v3) reports. Nothing here writes to a tenant or
//! contacts the people affected.

mod hibp;

pub use hibp::{hibp_from_config, Breach, Hibp, HIBP_ATTRIBUTION, HIBP_META};
