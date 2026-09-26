//! Pure builders for the objects a `SpectonRegistry` owns. No API calls here,
//! so everything is unit-testable.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{
    Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment,
};
use k8s_openapi::api::batch::v1::{CronJob, CronJobSpec, Job, JobSpec, JobTemplateSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource, EnvVar,
    EnvVarSource, HTTPGetAction, LocalObjectReference, PersistentVolumeClaimVolumeSource,
    PodSecurityContext, PodSpec, PodTemplateSpec, Probe, ResourceRequirements, SeccompProfile,
    SecretKeySelector, SecretVolumeSource, SecurityContext, Service, ServicePort, ServiceSpec,
    Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::{Resource, ResourceExt};
use sha2::{Digest, Sha256};

use super::{BackupSpec, ComponentSpec, SpectonRegistry};

pub const MANAGER: &str = "specton-operator";
pub const CONFIG_HASH_ANNOTATION: &str = "spectoncr.io/config-hash";
const CONFIG_DIR: &str = "/etc/spectoncr/config";
const KEYS_DIR: &str = "/etc/spectoncr/keys";
const NOBODY: i64 = 65534;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Registry,
    Auth,
}

impl Component {
    pub fn as_str(self) -> &'static str {
        match self {
            Component::Registry => "registry",
            Component::Auth => "auth",
        }
    }

    fn binary(self) -> &'static str {
        match self {
            Component::Registry => "specton-registry",
            Component::Auth => "specton-auth",
        }
    }

    fn default_port(self) -> i32 {
        match self {
            Component::Registry => 5000,
            Component::Auth => 5001,
        }
    }

    fn tmp_size(self) -> &'static str {
        match self {
            Component::Registry => "256Mi",
            Component::Auth => "64Mi",
        }
    }

    fn spec(self, cr: &SpectonRegistry) -> &ComponentSpec {
        match self {
            Component::Registry => &cr.spec.registry,
            Component::Auth => &cr.spec.auth,
        }
    }

    /// Name shared by the Deployment and the Service.
    pub fn object_name(self, cr: &SpectonRegistry) -> String {
        format!("{}-{}", cr.name_any(), self.as_str())
    }

    pub fn port(self, cr: &SpectonRegistry) -> i32 {
        self.spec(cr).port.unwrap_or(self.default_port())
    }
}

/// Selector labels. They match the Helm chart's, so NetworkPolicies and
/// ServiceMonitors keep selecting the pods when the `SpectonRegistry` has the
/// same name as the Helm release.
pub fn selector_labels(cr: &SpectonRegistry, component: Component) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "app.kubernetes.io/name".to_string(),
            format!("spectoncr-{}", component.as_str()),
        ),
        ("app.kubernetes.io/instance".to_string(), cr.name_any()),
        (
            "app.kubernetes.io/component".to_string(),
            component.as_str().to_string(),
        ),
    ])
}

fn common_labels(cr: &SpectonRegistry) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "app.kubernetes.io/part-of".to_string(),
            "spectoncr".to_string(),
        ),
        (
            "app.kubernetes.io/managed-by".to_string(),
            MANAGER.to_string(),
        ),
        ("app.kubernetes.io/instance".to_string(), cr.name_any()),
    ])
}

fn component_labels(cr: &SpectonRegistry, component: Component) -> BTreeMap<String, String> {
    let mut labels = common_labels(cr);
    labels.extend(selector_labels(cr, component));
    labels
}

fn owner_ref(cr: &SpectonRegistry) -> OwnerReference {
    cr.controller_owner_ref(&())
        .expect("SpectonRegistry from the API always has a name and uid")
}

fn meta(cr: &SpectonRegistry, name: String, labels: BTreeMap<String, String>) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: cr.namespace(),
        labels: Some(labels),
        owner_references: Some(vec![owner_ref(cr)]),
        ..Default::default()
    }
}

/// Short, stable hash used for config annotations and Job names.
pub fn short_hash(input: &[u8]) -> String {
    hex::encode(&Sha256::digest(input)[..8])
}

/// Kubernetes object names are capped at 63 characters for Jobs (the name
/// becomes a pod label). Truncate the prefix, never the unique suffix.
fn bounded_name(prefix: &str, suffix: &str) -> String {
    let max_prefix = 63 - suffix.len() - 1;
    let prefix = &prefix[..prefix.len().min(max_prefix)];
    format!("{}-{suffix}", prefix.trim_end_matches('-'))
}

pub fn deployment(
    cr: &SpectonRegistry,
    component: Component,
    image: &str,
    config_hash: &str,
) -> Deployment {
    let spec = component.spec(cr);
    let port = component.port(cr);
    let name = component.object_name(cr);
    let pinned = image.contains("@sha256:");
    let pull_policy = cr.spec.image.pull_policy.clone().unwrap_or_else(|| {
        // A digest never changes content, so there is nothing to re-pull.
        if pinned { "IfNotPresent" } else { "Always" }.to_string()
    });

    let binary = component.binary();
    let mut volume_mounts = vec![
        mount("config", CONFIG_DIR, true),
        mount("signing-keys", KEYS_DIR, true),
        mount("tmp", "/tmp", false),
    ];
    let mut volumes = vec![
        Volume {
            name: "config".into(),
            config_map: Some(ConfigMapVolumeSource {
                name: cr.spec.config_map_name.clone(),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "signing-keys".into(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(cr.spec.signing_key_secret.clone()),
                default_mode: Some(0o440),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "tmp".into(),
            empty_dir: Some(EmptyDirVolumeSource {
                size_limit: Some(Quantity(component.tmp_size().into())),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    let mut strategy = DeploymentStrategy {
        type_: Some("RollingUpdate".into()),
        rolling_update: Some(RollingUpdateDeployment {
            max_unavailable: Some(IntOrString::Int(0)),
            max_surge: Some(IntOrString::Int(1)),
        }),
    };

    if component == Component::Registry
        && let Some(claim) = &cr.spec.storage.pvc_claim_name
    {
        volume_mounts.push(mount("data", &cr.spec.storage.mount_path, false));
        volumes.push(Volume {
            name: "data".into(),
            persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                claim_name: claim.clone(),
                read_only: None,
            }),
            ..Default::default()
        });
        strategy = DeploymentStrategy {
            type_: Some("Recreate".into()),
            rolling_update: None,
        };
    }
    volume_mounts.extend(spec.extra_volume_mounts.iter().cloned());
    volumes.extend(spec.extra_volumes.iter().cloned());

    let mut annotations = spec.pod_annotations.clone();
    annotations.insert(CONFIG_HASH_ANNOTATION.into(), config_hash.into());

    let probe = |initial: i32, period: i32, timeout: i32, failures: i32| Probe {
        http_get: Some(HTTPGetAction {
            path: Some("/health".into()),
            port: IntOrString::String("http".into()),
            ..Default::default()
        }),
        initial_delay_seconds: Some(initial),
        period_seconds: Some(period),
        timeout_seconds: Some(timeout),
        failure_threshold: Some(failures),
        ..Default::default()
    };

    let container = Container {
        name: component.as_str().into(),
        image: Some(image.into()),
        image_pull_policy: Some(pull_policy),
        args: Some(vec![
            binary.into(),
            "serve".into(),
            format!("--config={CONFIG_DIR}/{}.yaml", component.as_str()),
        ]),
        ports: Some(vec![ContainerPort {
            name: Some("http".into()),
            container_port: port,
            protocol: Some("TCP".into()),
            ..Default::default()
        }]),
        env: (!spec.env.is_empty()).then(|| spec.env.clone()),
        env_from: (!spec.env_from.is_empty()).then(|| spec.env_from.clone()),
        liveness_probe: Some(probe(10, 15, 5, 3)),
        readiness_probe: Some(probe(5, 10, 3, 2)),
        startup_probe: Some(probe(5, 5, 5, 12)),
        resources: Some(
            spec.resources
                .clone()
                .unwrap_or_else(|| default_resources(component)),
        ),
        security_context: Some(SecurityContext {
            read_only_root_filesystem: Some(true),
            allow_privilege_escalation: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".into()]),
                add: None,
            }),
            ..Default::default()
        }),
        volume_mounts: Some(volume_mounts),
        ..Default::default()
    };

    let selector = selector_labels(cr, component);
    Deployment {
        metadata: meta(cr, name, component_labels(cr, component)),
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas.unwrap_or(2)),
            selector: LabelSelector {
                match_labels: Some(selector.clone()),
                match_expressions: None,
            },
            strategy: Some(strategy),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(selector),
                    annotations: Some(annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(volumes),
                    service_account_name: cr.spec.service_account_name.clone(),
                    automount_service_account_token: Some(false),
                    termination_grace_period_seconds: Some(30),
                    image_pull_secrets: pull_secrets(cr),
                    node_selector: (!spec.node_selector.is_empty())
                        .then(|| spec.node_selector.clone()),
                    tolerations: (!spec.tolerations.is_empty()).then(|| spec.tolerations.clone()),
                    security_context: Some(PodSecurityContext {
                        run_as_non_root: Some(true),
                        run_as_user: Some(NOBODY),
                        run_as_group: Some(NOBODY),
                        fs_group: Some(NOBODY),
                        seccomp_profile: Some(SeccompProfile {
                            type_: "RuntimeDefault".into(),
                            localhost_profile: None,
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        status: None,
    }
}

fn default_resources(component: Component) -> ResourceRequirements {
    let q = |s: &str| Quantity(s.into());
    let (req_cpu, req_mem, lim_cpu, lim_mem) = match component {
        Component::Registry => ("250m", "256Mi", "1", "512Mi"),
        Component::Auth => ("100m", "128Mi", "500m", "256Mi"),
    };
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".into(), q(req_cpu)),
            ("memory".into(), q(req_mem)),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".into(), q(lim_cpu)),
            ("memory".into(), q(lim_mem)),
        ])),
        claims: None,
    }
}

fn mount(name: &str, path: &str, read_only: bool) -> VolumeMount {
    VolumeMount {
        name: name.into(),
        mount_path: path.into(),
        read_only: read_only.then_some(true),
        ..Default::default()
    }
}

fn pull_secrets(cr: &SpectonRegistry) -> Option<Vec<LocalObjectReference>> {
    (!cr.spec.image_pull_secrets.is_empty()).then(|| {
        cr.spec
            .image_pull_secrets
            .iter()
            .map(|name| LocalObjectReference { name: name.clone() })
            .collect()
    })
}

pub fn service(cr: &SpectonRegistry, component: Component) -> Service {
    Service {
        metadata: meta(
            cr,
            component.object_name(cr),
            component_labels(cr, component),
        ),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".into()),
            selector: Some(selector_labels(cr, component)),
            ports: Some(vec![ServicePort {
                name: Some("http".into()),
                port: component.port(cr),
                target_port: Some(IntOrString::String("http".into())),
                protocol: Some("TCP".into()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    }
}

pub fn backup_cronjob_name(cr: &SpectonRegistry) -> String {
    format!("{}-backup", cr.name_any())
}

/// Name of the pre-upgrade backup Job for one upgrade attempt. Stable while
/// the attempt is in flight, so re-reconciling finds the same Job. Keyed on
/// both images and the spec generation, so a later upgrade to a version that
/// was backed up before still gets a fresh backup, and fixing the backup
/// settings after a failure (a spec change) retries with a new Job.
pub fn preupgrade_job_name(cr: &SpectonRegistry, from_image: &str, to_image: &str) -> String {
    let key = format!(
        "{}:{from_image}->{to_image}",
        cr.metadata.generation.unwrap_or_default()
    );
    bounded_name(
        &format!("{}-preupgrade", cr.name_any()),
        &short_hash(key.as_bytes()),
    )
}

fn backup_pod(backup: &BackupSpec, pull: Option<Vec<LocalObjectReference>>) -> PodTemplateSpec {
    let pg = &backup.postgres;
    let secret_env = |name: &str, key: &str| EnvVar {
        name: name.into(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                name: pg.secret_name.clone(),
                key: key.into(),
                optional: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    // Custom format (-Fc) is compressed by pg_dump itself, so there is no
    // pipe to hide a pg_dump failure from `set -e` (`pg_dump | gzip` exits 0
    // when the dump fails). The dump is verified with pg_restore and only
    // then renamed into place, so a bad run never looks like a good backup.
    let script = format!(
        "set -eu\n\
         f=/backup/\"$PGDATABASE\"-$(date -u +%Y%m%dT%H%M%SZ).dump\n\
         trap 'rm -f \"$f.tmp\"' EXIT\n\
         pg_dump -h {host} -p {port} --no-owner -Fc -f \"$f.tmp\"\n\
         pg_restore --list \"$f.tmp\" > /dev/null\n\
         mv \"$f.tmp\" \"$f\"\n\
         echo \"wrote $f\"\n\
         find /backup -name '*.dump' -mtime +{retention} -print -delete\n",
        host = pg.host,
        port = pg.port,
        retention = backup.retention_days,
    );
    PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/component".to_string(),
                "backup".to_string(),
            )])),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            restart_policy: Some("Never".into()),
            image_pull_secrets: pull,
            containers: vec![Container {
                name: "pg-dump".into(),
                image: Some(backup.image.clone()),
                command: Some(vec!["sh".into(), "-c".into(), script]),
                env: Some(vec![
                    secret_env("PGUSER", &pg.username_key),
                    secret_env("PGPASSWORD", &pg.password_key),
                    secret_env("PGDATABASE", &pg.database_key),
                ]),
                volume_mounts: Some(vec![mount("backup", "/backup", false)]),
                ..Default::default()
            }],
            volumes: Some(vec![Volume {
                name: "backup".into(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: backup.pvc_claim_name.clone(),
                    read_only: None,
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
    }
}

fn backup_job_spec(backup: &BackupSpec, cr: &SpectonRegistry) -> JobSpec {
    JobSpec {
        backoff_limit: Some(2),
        ttl_seconds_after_finished: Some(7 * 24 * 3600),
        template: backup_pod(backup, pull_secrets(cr)),
        ..Default::default()
    }
}

pub fn backup_cronjob(cr: &SpectonRegistry, backup: &BackupSpec) -> CronJob {
    let mut labels = common_labels(cr);
    labels.insert("app.kubernetes.io/component".into(), "backup".into());
    CronJob {
        metadata: meta(cr, backup_cronjob_name(cr), labels),
        spec: Some(CronJobSpec {
            schedule: backup.schedule.clone(),
            concurrency_policy: Some("Forbid".into()),
            successful_jobs_history_limit: Some(3),
            failed_jobs_history_limit: Some(3),
            job_template: JobTemplateSpec {
                metadata: None,
                spec: Some(backup_job_spec(backup, cr)),
            },
            ..Default::default()
        }),
        status: None,
    }
}

pub fn preupgrade_job(
    cr: &SpectonRegistry,
    backup: &BackupSpec,
    from_image: &str,
    to_image: &str,
) -> Job {
    let mut labels = common_labels(cr);
    labels.insert("app.kubernetes.io/component".into(), "backup".into());
    let mut job_meta = meta(cr, preupgrade_job_name(cr, from_image, to_image), labels);
    job_meta.annotations = Some(BTreeMap::from([
        (
            "spectoncr.io/from-image".to_string(),
            from_image.to_string(),
        ),
        ("spectoncr.io/to-image".to_string(), to_image.to_string()),
    ]));
    Job {
        metadata: job_meta,
        spec: Some(backup_job_spec(backup, cr)),
        status: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::{PostgresRef, SpectonRegistrySpec};

    fn cr(spec_json: serde_json::Value) -> SpectonRegistry {
        let spec: SpectonRegistrySpec = serde_json::from_value(spec_json).unwrap();
        let mut cr = SpectonRegistry::new("spectoncr", spec);
        cr.metadata.namespace = Some("acc".into());
        cr.metadata.uid = Some("0000-uid".into());
        cr
    }

    fn minimal() -> SpectonRegistry {
        cr(serde_json::json!({
            "configMapName": "spectoncr-config",
            "signingKeySecret": "spectoncr-jwt",
        }))
    }

    fn container(d: &Deployment) -> &Container {
        &d.spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
    }

    #[test]
    fn spec_defaults_apply() {
        let cr = minimal();
        assert_eq!(cr.spec.image.repository, "ghcr.io/spectonio/spectoncr");
        assert_eq!(cr.spec.image.tag, "latest");
        assert!(!cr.spec.auto_update.enabled);
        assert_eq!(cr.spec.auto_update.interval_seconds, 300);
        assert_eq!(Component::Registry.port(&cr), 5000);
        assert_eq!(Component::Auth.port(&cr), 5001);
    }

    #[test]
    fn registry_deployment_matches_chart_shape() {
        let cr = minimal();
        let d = deployment(&cr, Component::Registry, "repo:tag", "abc");
        assert_eq!(d.metadata.name.as_deref(), Some("spectoncr-registry"));
        assert_eq!(d.metadata.namespace.as_deref(), Some("acc"));
        let owner = &d.metadata.owner_references.as_ref().unwrap()[0];
        assert_eq!(owner.kind, "SpectonRegistry");
        assert_eq!(owner.controller, Some(true));

        let spec = d.spec.as_ref().unwrap();
        assert_eq!(spec.replicas, Some(2));
        let sel = spec.selector.match_labels.as_ref().unwrap();
        assert_eq!(sel["app.kubernetes.io/name"], "spectoncr-registry");
        assert_eq!(sel["app.kubernetes.io/instance"], "spectoncr");
        assert_eq!(
            spec.strategy.as_ref().unwrap().type_.as_deref(),
            Some("RollingUpdate")
        );

        let c = container(&d);
        assert_eq!(c.image.as_deref(), Some("repo:tag"));
        assert_eq!(c.image_pull_policy.as_deref(), Some("Always"));
        assert_eq!(
            c.args.as_ref().unwrap(),
            &vec![
                "specton-registry".to_string(),
                "serve".into(),
                "--config=/etc/spectoncr/config/registry.yaml".into()
            ]
        );
        assert_eq!(c.ports.as_ref().unwrap()[0].container_port, 5000);

        let annotations = spec
            .template
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .as_ref()
            .unwrap();
        assert_eq!(annotations[CONFIG_HASH_ANNOTATION], "abc");
    }

    #[test]
    fn auth_deployment_uses_auth_binary_and_port() {
        let cr = minimal();
        let d = deployment(&cr, Component::Auth, "repo:tag", "abc");
        assert_eq!(d.metadata.name.as_deref(), Some("spectoncr-auth"));
        let c = container(&d);
        assert_eq!(c.args.as_ref().unwrap()[0], "specton-auth");
        assert_eq!(
            c.args.as_ref().unwrap()[2],
            "--config=/etc/spectoncr/config/auth.yaml"
        );
        assert_eq!(c.ports.as_ref().unwrap()[0].container_port, 5001);
    }

    #[test]
    fn digest_pinned_image_is_not_repulled() {
        let cr = minimal();
        let d = deployment(&cr, Component::Registry, "repo@sha256:abcd", "h");
        assert_eq!(
            container(&d).image_pull_policy.as_deref(),
            Some("IfNotPresent")
        );
    }

    #[test]
    fn filesystem_storage_uses_recreate_and_mounts_pvc() {
        let cr = cr(serde_json::json!({
            "configMapName": "c",
            "signingKeySecret": "k",
            "storage": { "pvcClaimName": "spectoncr-data" },
        }));
        let d = deployment(&cr, Component::Registry, "i", "h");
        let spec = d.spec.as_ref().unwrap();
        assert_eq!(
            spec.strategy.as_ref().unwrap().type_.as_deref(),
            Some("Recreate")
        );
        let mounts = container(&d).volume_mounts.as_ref().unwrap();
        assert!(
            mounts
                .iter()
                .any(|m| m.name == "data" && m.mount_path == "/var/lib/spectoncr/data")
        );

        // Auth never mounts the registry's data volume.
        let auth = deployment(&cr, Component::Auth, "i", "h");
        assert!(
            !container(&auth)
                .volume_mounts
                .as_ref()
                .unwrap()
                .iter()
                .any(|m| m.name == "data")
        );
    }

    #[test]
    fn service_targets_component_pods() {
        let cr = minimal();
        let svc = service(&cr, Component::Auth);
        let spec = svc.spec.unwrap();
        assert_eq!(svc.metadata.name.as_deref(), Some("spectoncr-auth"));
        assert_eq!(
            spec.selector.unwrap()["app.kubernetes.io/component"],
            "auth"
        );
        assert_eq!(spec.ports.unwrap()[0].port, 5001);
    }

    fn backup() -> BackupSpec {
        BackupSpec {
            schedule: "0 2 * * *".into(),
            before_upgrade: true,
            postgres: PostgresRef {
                host: "spectoncr-postgres".into(),
                port: 5432,
                secret_name: "spectoncr-postgres".into(),
                username_key: "username".into(),
                password_key: "password".into(),
                database_key: "database".into(),
            },
            pvc_claim_name: "spectoncr-backups".into(),
            retention_days: 7,
            image: "postgres:16-alpine".into(),
        }
    }

    #[test]
    fn backup_cronjob_dumps_to_pvc() {
        let cr = minimal();
        let cj = backup_cronjob(&cr, &backup());
        let spec = cj.spec.unwrap();
        assert_eq!(spec.concurrency_policy.as_deref(), Some("Forbid"));
        let pod = spec.job_template.spec.unwrap().template.spec.unwrap();
        let script = &pod.containers[0].command.as_ref().unwrap()[2];
        assert!(script.contains("pg_dump -h spectoncr-postgres -p 5432"));
        assert!(!script.contains('|'), "a pipe would mask pg_dump failures");
        assert!(script.contains("pg_restore --list"));
        assert!(script.contains("-mtime +7"));
        assert_eq!(
            pod.volumes.unwrap()[0]
                .persistent_volume_claim
                .as_ref()
                .unwrap()
                .claim_name,
            "spectoncr-backups"
        );
    }

    #[test]
    fn preupgrade_job_name_is_stable_and_bounded() {
        let mut cr = minimal();
        cr.metadata.generation = Some(3);
        let a = preupgrade_job_name(&cr, "repo:v1", "repo:v2");
        assert_eq!(a, preupgrade_job_name(&cr, "repo:v1", "repo:v2"));
        // Going back to v2 later is a new upgrade and needs a new backup.
        assert_ne!(a, preupgrade_job_name(&cr, "repo:v3", "repo:v2"));
        // A spec edit (e.g. fixing the backup host) retries with a new Job.
        cr.metadata.generation = Some(4);
        assert_ne!(a, preupgrade_job_name(&cr, "repo:v1", "repo:v2"));

        cr.metadata.name = Some("x".repeat(80));
        let long = preupgrade_job_name(&cr, "repo:v1", "repo:v2");
        assert!(long.len() <= 63, "{} chars", long.len());
    }
}
