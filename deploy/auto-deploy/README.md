# Pull-based image auto-deploy

Automatically rolls the `acc` spectoncr Deployments when a new
`bwalia/spectoncr:latest` is published — **without** any inbound access to the
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
 CI (build)                         cluster (acc)
 ──────────                         ─────────────
 docker-hub-publish.yml             CronJob spectoncr-image-updater  (*/5 min)
   push bwalia/spectoncr:latest ──▶   polls Docker Hub for :latest digest
                                       digest changed?  → kubectl patch (roll)
                                       registry + auth re-pull :latest
                                       (pullPolicy: Always)
```

## What's in `image-updater.yaml`

| Resource | Purpose |
| --- | --- |
| ServiceAccount + Role + RoleBinding | scoped to **get/patch Deployments in `acc` only** |
| CronJob `spectoncr-image-updater` | every 5 min: compare Docker Hub `:latest` digest to each Deployment's `spectoncr.io/image-digest` annotation; on change, patch a new `rolled-at` + digest annotation to trigger a rollout |

The digest is tracked in a pod-template annotation, so a roll happens **only**
when the published image actually changes (no restart loops).

## Operate

```bash
export KUBECONFIG=~/.kube/k3s1.yaml
kubectl -n acc get cronjob spectoncr-image-updater
kubectl -n acc create job manual-check --from=cronjob/spectoncr-image-updater   # run now
kubectl -n acc logs job/manual-check
kubectl -n acc patch cronjob spectoncr-image-updater -p '{"spec":{"suspend":true}}'  # pause
kubectl delete -f deploy/auto-deploy/image-updater.yaml                          # remove
```

Change the polled image or targets via the CronJob env (`REPO`, `NS`,
`DEPLOYMENTS`). To extend to another environment, copy the manifest and adjust
the namespace.
