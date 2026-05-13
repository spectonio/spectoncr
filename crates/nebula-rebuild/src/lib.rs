//! NebulaCR auto-rebuild on base CVE patch.
//!
//! Slice 1 ships the lineage extractor (label-based + history-based)
//! and the schema. The subscription reconciler + emitters
//! (GitHub/GitLab/Tekton/webhook) ship in slices 2-3.

pub mod lineage;

pub use lineage::{detect_lineage, LineageHint, LineageConfidence};
