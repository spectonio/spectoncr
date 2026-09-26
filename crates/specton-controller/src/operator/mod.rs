//! Lifecycle operator for SpectonCR installations.
//!
//! A `SpectonRegistry` resource describes one registry installation (the
//! registry + auth Deployments and their Services). The operator owns those
//! workloads and drives their lifecycle:
//!
//! - **Install / drift repair**: Deployments and Services are server-side
//!   applied on every reconcile, so manual edits are reverted.
//! - **Config rollouts**: pods carry a hash of the referenced ConfigMap, so
//!   editing the config rolls the pods.
//! - **Ordered upgrades**: on an image change the operator optionally takes a
//!   Postgres backup, then rolls auth, waits for it, then rolls the registry
//!   (which runs the schema migrations on start).
//! - **Auto-update**: optionally tracks the digest behind a tag (e.g.
//!   `:latest`) and pins pods to `repo@sha256:…`, rolling when it moves.
//! - **Backups**: optional scheduled `pg_dump` CronJob with retention.
//!
//! Everything the operator creates carries an owner reference to the
//! `SpectonRegistry`, so deleting it garbage-collects the workloads. Data
//! volumes (PVCs) are only referenced, never owned, so they survive.

pub mod image;
pub mod reconcile;
pub mod resources;

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    EnvFromSource, EnvVar, ResourceRequirements, Toleration, Volume, VolumeMount,
};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const DEFAULT_REPOSITORY: &str = "ghcr.io/spectonio/spectoncr";
pub const DEFAULT_TAG: &str = "latest";

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "SpectonRegistry",
    plural = "spectonregistries",
    shortname = "scr",
    category = "spectoncr",
    status = "SpectonRegistryStatus",
    namespaced,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Image","type":"string","jsonPath":".status.currentImage","priority":1}"#,
    printcolumn = r#"{"name":"Registry","type":"string","jsonPath":".status.registry.summary"}"#,
    printcolumn = r#"{"name":"Auth","type":"string","jsonPath":".status.auth.summary"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SpectonRegistrySpec {
    #[serde(default)]
    pub image: ImageSpec,
    /// ConfigMap holding `registry.yaml` and `auth.yaml`, mounted at
    /// `/etc/spectoncr/config`.
    pub config_map_name: String,
    /// Secret holding the JWT signing keypair, mounted at `/etc/spectoncr/keys`.
    pub signing_key_secret: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    #[serde(default)]
    pub registry: ComponentSpec,
    #[serde(default)]
    pub auth: ComponentSpec,
    #[serde(default)]
    pub storage: StorageSpec,
    #[serde(default)]
    pub auto_update: AutoUpdateSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupSpec>,
    /// Stop touching the workloads (maintenance mode). Existing pods keep running.
    #[serde(default)]
    pub paused: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageSpec {
    #[serde(default = "default_repository")]
    pub repository: String,
    #[serde(default = "default_tag")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<String>,
}

impl Default for ImageSpec {
    fn default() -> Self {
        Self {
            repository: default_repository(),
            tag: default_tag(),
            pull_policy: None,
        }
    }
}

fn default_repository() -> String {
    DEFAULT_REPOSITORY.to_string()
}

fn default_tag() -> String {
    DEFAULT_TAG.to_string()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ComponentSpec {
    /// Defaults to 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    /// Container/Service port. Defaults to 5000 (registry) / 5001 (auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_selector: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<Toleration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from: Vec<EnvFromSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_volumes: Vec<Volume>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_volume_mounts: Vec<VolumeMount>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageSpec {
    /// Existing PVC for the filesystem storage backend. When set, the registry
    /// uses the Recreate strategy (a ReadWriteOnce volume can't be shared
    /// between the old and new pod during a rolling update).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pvc_claim_name: Option<String>,
    #[serde(default = "default_mount_path")]
    pub mount_path: String,
}

impl Default for StorageSpec {
    fn default() -> Self {
        Self {
            pvc_claim_name: None,
            mount_path: default_mount_path(),
        }
    }
}

fn default_mount_path() -> String {
    "/var/lib/spectoncr/data".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoUpdateSpec {
    /// Track the digest behind `image.tag` and roll when it changes.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    /// Talk plain HTTP to the image registry (in-cluster registries).
    #[serde(default)]
    pub insecure: bool,
}

impl Default for AutoUpdateSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: default_interval(),
            insecure: false,
        }
    }
}

fn default_interval() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupSpec {
    /// Cron schedule for the backup CronJob. Empty disables scheduled backups
    /// (pre-upgrade backups still run when `beforeUpgrade` is set).
    #[serde(default = "default_schedule")]
    pub schedule: String,
    /// Take a backup and wait for it before rolling out a new image.
    #[serde(default = "default_true")]
    pub before_upgrade: bool,
    pub postgres: PostgresRef,
    /// PVC the dumps are written to.
    pub pvc_claim_name: String,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default = "default_backup_image")]
    pub image: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PostgresRef {
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: i32,
    /// Secret with the connection credentials.
    pub secret_name: String,
    #[serde(default = "default_username_key")]
    pub username_key: String,
    #[serde(default = "default_password_key")]
    pub password_key: String,
    #[serde(default = "default_database_key")]
    pub database_key: String,
}

fn default_schedule() -> String {
    "0 2 * * *".to_string()
}
fn default_true() -> bool {
    true
}
fn default_retention() -> u32 {
    7
}
fn default_backup_image() -> String {
    "postgres:16-alpine".to_string()
}
fn default_pg_port() -> i32 {
    5432
}
fn default_username_key() -> String {
    "username".to_string()
}
fn default_password_key() -> String {
    "password".to_string()
}
fn default_database_key() -> String {
    "database".to_string()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SpectonRegistryStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// Image every pod is running once the last rollout completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_image: Option<String>,
    /// Image the operator is rolling towards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_image: Option<String>,
    /// Tag the resolved digest belongs to (`repo:tag`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracked_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_digest_check: Option<String>,
    #[serde(default)]
    pub registry: ComponentStatus,
    #[serde(default)]
    pub auth: ComponentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup: Option<BackupStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<OperatorCondition>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComponentStatus {
    #[serde(default)]
    pub desired: i32,
    #[serde(default)]
    pub ready: i32,
    #[serde(default)]
    pub updated: i32,
    /// `ready/desired`, for the printer column.
    #[serde(default)]
    pub summary: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatus {
    pub job_name: String,
    pub succeeded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_time: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OperatorCondition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
