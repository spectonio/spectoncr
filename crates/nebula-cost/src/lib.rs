//! NebulaCR usage / cost telemetry.
//!
//! Slice 1: UsageEvent shape + UsageRecorder trait + Postgres recorder.
//! The drainer task and rollup loop ship in slice 2; cost projection
//! and anomaly detection in slice 3.

pub mod cost;
pub mod recorder;

pub use cost::{CostModel, Dollars};
pub use recorder::{
    NoopUsageRecorder, PgUsageRecorder, UsageEvent, UsageOp, UsageRecorder, UsageSrc,
};
