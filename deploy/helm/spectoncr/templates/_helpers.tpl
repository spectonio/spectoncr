{{/*
Expand the name of the chart.
*/}}
{{- define "spectoncr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "spectoncr.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "spectoncr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "spectoncr.labels" -}}
helm.sh/chart: {{ include "spectoncr.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: spectoncr
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Registry selector labels
*/}}
{{- define "spectoncr.registry.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spectoncr.name" . }}-registry
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: registry
{{- end }}

{{/*
Registry labels
*/}}
{{- define "spectoncr.registry.labels" -}}
{{ include "spectoncr.labels" . }}
{{ include "spectoncr.registry.selectorLabels" . }}
{{- end }}

{{/*
Auth selector labels
*/}}
{{- define "spectoncr.auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spectoncr.name" . }}-auth
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: auth
{{- end }}

{{/*
Auth labels
*/}}
{{- define "spectoncr.auth.labels" -}}
{{ include "spectoncr.labels" . }}
{{ include "spectoncr.auth.selectorLabels" . }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "spectoncr.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "spectoncr.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Registry image
*/}}
{{- define "spectoncr.registry.image" -}}
{{- $tag := default .Chart.AppVersion .Values.registry.image.tag -}}
{{- printf "%s:%s" .Values.registry.image.repository $tag }}
{{- end }}

{{/*
Auth image
*/}}
{{- define "spectoncr.auth.image" -}}
{{- $tag := default .Chart.AppVersion .Values.auth.image.tag -}}
{{- printf "%s:%s" .Values.auth.image.repository $tag }}
{{- end }}

{{/*
Secret name for JWT signing keys
*/}}
{{- define "spectoncr.jwt.secretName" -}}
{{- if .Values.jwt.existingSecret }}
{{- .Values.jwt.existingSecret }}
{{- else }}
{{- printf "%s-jwt" (include "spectoncr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for S3 credentials
*/}}
{{- define "spectoncr.s3.secretName" -}}
{{- if .Values.storage.s3.existingSecret }}
{{- .Values.storage.s3.existingSecret }}
{{- else }}
{{- printf "%s-s3" (include "spectoncr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for GCS credentials
*/}}
{{- define "spectoncr.gcs.secretName" -}}
{{- if .Values.storage.gcs.existingSecret }}
{{- .Values.storage.gcs.existingSecret }}
{{- else }}
{{- printf "%s-gcs" (include "spectoncr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for Azure credentials
*/}}
{{- define "spectoncr.azure.secretName" -}}
{{- if .Values.storage.azure.existingSecret }}
{{- .Values.storage.azure.existingSecret }}
{{- else }}
{{- printf "%s-azure" (include "spectoncr.fullname" .) }}
{{- end }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "spectoncr.configMapName" -}}
{{- printf "%s-config" (include "spectoncr.fullname" .) }}
{{- end }}

{{/*
Upstream registry secret name
*/}}
{{/*
Validate JWT signing key configuration.
Fails the render if no signing key source is configured in production.
*/}}
{{- define "spectoncr.jwt.validate" -}}
{{- if and (not .Values.jwt.existingSecret) (not .Values.jwt.signingKey) }}
{{- fail "SECURITY: jwt.existingSecret or jwt.signingKey must be set. Running with embedded dev keys is not supported. Generate keys with: openssl genrsa -out signing.pem 2048 && openssl rsa -in signing.pem -pubout -out verification.pem" }}
{{- end }}
{{- end }}

{{/*
Postgres (scanner metadata store).
*/}}
{{- define "spectoncr.postgres.fullname" -}}
{{- printf "%s-postgres" (include "spectoncr.fullname" .) -}}
{{- end }}

{{- define "spectoncr.postgres.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spectoncr.name" . }}-postgres
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end }}

{{- define "spectoncr.postgres.labels" -}}
{{ include "spectoncr.labels" . }}
{{ include "spectoncr.postgres.selectorLabels" . }}
{{- end }}

{{- define "spectoncr.postgres.secretName" -}}
{{- if .Values.postgres.existingSecret }}
{{- .Values.postgres.existingSecret }}
{{- else }}
{{- printf "%s-postgres" (include "spectoncr.fullname" .) -}}
{{- end }}
{{- end }}

{{/*
Resolve a postgres password. Priority: user-supplied → existing in-cluster
secret → fresh 24-char random. The lookup preserves the generated password
across helm upgrades so the registry doesn't break after re-render.
*/}}
{{- define "spectoncr.postgres.password" -}}
{{- if .Values.postgres.password -}}
{{- .Values.postgres.password -}}
{{- else -}}
  {{- $secretName := printf "%s-postgres" (include "spectoncr.fullname" .) -}}
  {{- $existing := lookup "v1" "Secret" .Release.Namespace $secretName -}}
  {{- if and $existing $existing.data (index $existing.data "password") -}}
    {{- index $existing.data "password" | b64dec -}}
  {{- else -}}
    {{- randAlphaNum 24 -}}
  {{- end -}}
{{- end -}}
{{- end }}

{{- define "spectoncr.scanner.postgresUrl" -}}
{{- $user := .Values.postgres.username | default "spectoncr" -}}
{{- $db := .Values.postgres.database | default "spectoncr" -}}
{{- $host := printf "%s.%s.svc.cluster.local" (include "spectoncr.postgres.fullname" .) .Release.Namespace -}}
{{- printf "postgres://%s:$(SPECTONCR_POSTGRES_PASSWORD)@%s:5432/%s?sslmode=disable" $user $host $db -}}
{{- end }}

{{/*
Redis (scanner ephemeral result cache).
*/}}
{{- define "spectoncr.redis.fullname" -}}
{{- printf "%s-redis" (include "spectoncr.fullname" .) -}}
{{- end }}

{{- define "spectoncr.redis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spectoncr.name" . }}-redis
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: redis
{{- end }}

{{- define "spectoncr.redis.labels" -}}
{{ include "spectoncr.labels" . }}
{{ include "spectoncr.redis.selectorLabels" . }}
{{- end }}

{{- define "spectoncr.scanner.redisUrl" -}}
{{- $host := printf "%s.%s.svc.cluster.local" (include "spectoncr.redis.fullname" .) .Release.Namespace -}}
{{- printf "redis://%s:6379" $host -}}
{{- end }}

{{/*
Upstream registry secret name
*/}}
{{- define "spectoncr.upstream.secretName" -}}
{{- $fullname := index . 0 -}}
{{- $name := index . 1 -}}
{{- $upstream := index . 2 -}}
{{- if $upstream.existingSecret }}
{{- $upstream.existingSecret }}
{{- else }}
{{- printf "%s-upstream-%s" $fullname ($name | replace "." "-") }}
{{- end }}
{{- end }}
