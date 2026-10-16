//! SpectonCR auto-rebuild on base CVE patch.
//!
//! - **R1:** lineage extractor + schema
//! - **R2:** subscriptions store, GitHub dispatch fire path, rate limit,
//!   registry `/v2/_rebuild/*` + `/v2/_lineage/{digest}`
//! - **R3:** GitLab / Tekton / webhook emitters wired end-to-end

pub mod emitter;
pub mod lineage;
pub mod rate_limit;
pub mod service;
pub mod subscription;

pub use emitter::{
    EmitError, GenericWebhookEmitter, GitHubDispatchEmitter, GitLabPipelineEmitter, RebuildEmitter,
    RebuildEvent, TektonEventListenerEmitter, TriggerCause, compute_webhook_signature,
};
pub use lineage::{LineageConfidence, LineageHint, detect_lineage};
pub use rate_limit::{RateLimit, RateLimitError, current_bucket};
pub use service::{FireError, FireRequest, FireResult, RebuildService};
pub use subscription::{
    EmitterSpec, PgSubscriptionStore, RateLimitSpec, RebuildSubscription, SubscriptionSpec,
    SubscriptionStore, SubscriptionStoreError, TriggersSpec, WatchSpec, glob_match,
};
