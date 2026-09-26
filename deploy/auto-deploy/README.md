# Pull-based image auto-deploy

Automatically rolls the spectoncr registry, auth and mirror Deployments in `acc`, `int` and `test` when
a new `bwalia/spectoncr:latest` is published — **without** any inbound access to the
cluster.

## Why not a GitHub Actions deploy?

The acc `spectoncr` Helm release is owned by `bwalia/diy-tax-return-uk`
(`devops/helm-charts/spectoncr`, deployed by its `deploy-spectoncr.yml`). The
chart in this repo lags behind it, so this repo must not push chart deploys to
acc; `.github/workflows/deploy-k3s.yml` is manual-only and needs an explicit
confirmation for that reason. (It used to also be blocked by the k3s API being
firewalled, but GitHub-hosted runners can reach k3s1 now.) Only the image
rolls from here: the cluster reaches *out* to Docker Hub.

```
 CI (build)                         cluster (acc, int, test)
 ──────────                         ─────────────
 docker-hub-publish.yml             CronJob spectoncr-image-updater  (*/5 min)
   push bwalia/spectoncr:latest ──▶   polls Docker Hub for :latest digest
                                       digest changed?  → kubectl patch (roll)
                                       registry + auth re-pull :latest
                                       (pullPolicy: Always)
```

## Layout

```
deploy/auto-deploy/
  base/image-updater.yaml     ServiceAccount + Role + RoleBinding + CronJob (no namespace)
  overlays/acc|int|test/      kustomize overlay per namespace
```

| Resource | Purpose |
| --- | --- |
| ServiceAccount + Role + RoleBinding | scoped to **get/patch Deployments in the overlay's namespace only** |
| CronJob `spectoncr-image-updater` | every 5 min: compare Docker Hub `:latest` digest to each Deployment's `spectoncr.io/image-digest` annotation; on change, patch a new `rolled-at` + digest annotation to trigger a rollout |

The CronJob reads its namespace from the pod (`metadata.namespace`), so the
overlays differ only in `namespace:`. The digest is tracked in a pod-template
annotation, so a roll happens **only** when the published image actually
changes (no restart loops). The first run in a namespace rolls once, to record
the digest.

Rolls are zero-downtime because registry and auth run 2 replicas with a
rolling update and a preStop drain (diy-tax-return-uk chart).

## Operate

```bash
export KUBECONFIG=~/.kube/k3s1.yaml
kubectl apply -k deploy/auto-deploy/overlays/int                        # install / update (acc|int|test)
kubectl -n int get cronjob spectoncr-image-updater
kubectl -n int create job manual-check --from=cronjob/spectoncr-image-updater   # run now
kubectl -n int logs job/manual-check
kubectl -n int patch cronjob spectoncr-image-updater -p '{"spec":{"suspend":true}}'  # pause
kubectl delete -k deploy/auto-deploy/overlays/int                       # remove
```

Change the polled image or target Deployments via the CronJob env (`REPO`,
`DEPLOYMENTS`) in `base/`. To add an environment, copy an overlay and change
its `namespace:`.
