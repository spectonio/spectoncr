# SpectonCR operator

`specton-controller` is the Kubernetes operator for SpectonCR. It reconciles
two groups of `spectoncr.io/v1alpha1` resources:

| Resource | What the operator does |
| --- | --- |
| `SpectonRegistry` | Installs and runs a registry: the registry and auth Deployments and Services, upgrades, backups |
| `Tenant`, `Project`, `AccessPolicy`, `TokenPolicy` | Syncs them to the auth service's admin API |

## Install

The operator ships in the main image and in the Helm chart, off by default:

```bash
helm upgrade --install spectoncr deploy/helm/spectoncr -n acc \
  -f deploy/helm/spectoncr/values-acc.yaml \
  --set operator.enabled=true
```

That adds a single-replica `<release>-operator` Deployment with a ClusterRole.
The CRDs are always installed with the chart. Enabling the operator changes
nothing until you create a `SpectonRegistry`.

## SpectonRegistry

See `examples/kubernetes/spectonregistry.yaml` for a full example. You provide
the ConfigMap (`registry.yaml`, `auth.yaml`) and the JWT signing-key Secret; the
operator creates the rest.

```console
$ kubectl -n acc get scr
NAME        PHASE   REGISTRY   AUTH   AGE
spectoncr   Ready   2/2        2/2    3d
```

### Lifecycle

- **Install and drift repair.** Deployments and Services are server-side
  applied on every reconcile, so a manual `kubectl scale` or edit is reverted.
  Change the `SpectonRegistry` instead.
- **Config changes.** Pods carry a hash of the ConfigMap
  (`spectoncr.io/config-hash`), and the operator watches the ConfigMap, so an
  edit rolls the pods straight away.
- **Upgrades.** Changing `spec.image.tag` (or a new digest under auto-update)
  runs in order:
  1. If `backup.beforeUpgrade` is set, a `pg_dump` Job runs first. The upgrade
     waits for it (phase `BackingUp`). If the backup fails, the upgrade stops
     with phase `Degraded` / reason `UpgradeBlocked`, and both Deployments stay
     on the old image. Fixing `spec.backup` retries automatically; setting
     `beforeUpgrade: false` skips the backup.
  2. Auth rolls out first. The operator waits until every auth pod is updated
     and available.
  3. Then the registry rolls out. The registry runs the schema migrations on
     start, so it goes last.
- **Auto-update.** With `autoUpdate.enabled`, the operator resolves the digest
  behind the tag every `intervalSeconds` and pins pods to `repo@sha256:…`
  (pull policy `IfNotPresent`). When the digest moves, it runs the upgrade
  above. This replaces `deploy/auto-deploy/image-updater.yaml`. Only public
  images are supported (anonymous token auth). Use `autoUpdate.insecure: true`
  for a plain-HTTP in-cluster registry.
- **Backups.** `backup.schedule` creates a `<name>-backup` CronJob that writes
  `pg_dump -Fc` files to `backup.pvcClaimName`. Each file is checked with
  `pg_restore --list` before it is kept, and files older than `retentionDays`
  are deleted. Restore with
  `pg_restore -h <host> -U <user> -d <db> --clean <file>.dump`.
- **Pause.** `spec.paused: true` stops the operator touching the workloads
  (phase `Paused`). Running pods are left alone.
- **Delete.** Deleting the `SpectonRegistry` deletes everything the operator
  created (via owner references). PVCs and Secrets are only referenced, never
  owned, so data survives.

### Status

`status.phase` is one of `Pending`, `Progressing`, `BackingUp`, `Upgrading`,
`Ready`, `Degraded` or `Paused`. The `Ready` condition's reason and message say
what the operator is waiting for. The operator also emits a Kubernetes Event on
every phase change.

```bash
kubectl -n acc get scr spectoncr -o jsonpath='{.status.conditions}' | jq
kubectl -n acc get events --field-selector involvedObject.kind=SpectonRegistry
```

## Migrating a Helm-managed install

The operator names its objects `<name>-registry` / `<name>-auth` and uses the
chart's selector labels. A `SpectonRegistry` with the same name as the Helm
release is designed to take over the existing Deployments and Services in
place (server-side apply with force), so Service DNS, the Ingress,
NetworkPolicies and ServiceMonitors keep working. This has not been tested
against a live Helm release yet; try it on a scratch namespace first.
Once it has taken over, stop Helm from rendering those Deployments and
Services, or the two will fight. The chart does not have a switch for this yet.

## Development

The CRD schema is generated from the Rust types. After changing them:

```bash
cargo run -p specton-controller -- crd   # then refresh templates/crds/spectonregistry.yaml
```

The controller has no leader election. Run exactly one replica (the chart
uses `strategy: Recreate`).
