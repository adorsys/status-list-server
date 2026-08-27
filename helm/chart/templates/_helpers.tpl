{{/*
Expand the name of the chart.
*/}}
{{- define "status-list-server-chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "status-list-server-chart.fullname" -}}
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
{{- define "status-list-server-chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "status-list-server-chart.labels" -}}
helm.sh/chart: {{ include "status-list-server-chart.chart" . }}
{{ include "status-list-server-chart.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "status-list-server-chart.selectorLabels" -}}
app: {{ include "status-list-server-chart.name" . }}
app.kubernetes.io/name: {{ include "status-list-server-chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "status-list-server-chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "status-list-server-chart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Effective name of the Kubernetes Secret the application reads (postgres password).
Single supported name: "statuslist-secret" in both ESO mode (ExternalSecret target) and
fallback mode. The Deployment, PostgreSQL (postgres.auth.existingSecret), and the fallback
Secret all reference this same name, so it is not independently configurable. ESO mode
validates externalSecret.spec.target.name against it at render time.
*/}}
{{- define "status-list-server-chart.appSecretName" -}}
{{- "statuslist-secret" }}
{{- end }}

{{/*
Effective AWS region for the application (renders APP_AWS__REGION for the AWS secretStore
provider). Preference: explicit statuslist.aws.region, then the legacy secretStore.aws.region
(upgrade-compatible fallback). Returns empty when neither is set, so APP_AWS__REGION is opt-in
(explicitly configured) rather than injected unconditionally for non-AWS providers.
*/}}
{{- define "status-list-server-chart.appRegion" -}}
{{- $r := .Values.statuslist.aws.region }}
{{- if not $r }}
{{- $r = .Values.secretStore.aws.region }}
{{- end }}
{{- $r }}
{{- end }}

{{/*
Resolve the Redis connection URI based on chart values. Only meaningful when the
redis-ha subchart is enabled (redis-ha.enabled=true). Uses the same single
application-secret name as PostgreSQL (REDIS_PASSWORD secretKeyRef).

The password is intentionally NOT embedded in the URI: the Deployment exposes it
as the REDIS_PASSWORD env var (secretKeyRef) so the application authenticates with
it separately, avoiding credential leakage in the URL string and any URI-encoding
issues from special characters in the password.
*/}}
{{- define "status-list-server-chart.redisUri" -}}
{{- $redisHA := index .Values "redis-ha" | default dict -}}
{{- $redisCfg := index $redisHA "redis" | default dict -}}
{{- $haproxy := index $redisHA "haproxy" | default dict -}}
{{- $haproxyEnabled := default true (index $haproxy "enabled") -}}
{{- $haproxyTls := index $haproxy "tls" | default dict -}}
{{- $tlsEnabled := and $haproxyEnabled (eq (default false (index $haproxyTls "enabled")) true) -}}
{{- $externalHostname := default "" (index $redisHA "externalDnsHostname") -}}
{{- $port := default 6379 (index $redisCfg "port") -}}
{{- $scheme := ternary "rediss" "redis" $tlsEnabled -}}
{{- $host := printf "%s-redis-ha-haproxy.%s.svc.cluster.local" .Release.Name .Release.Namespace -}}
{{- if not $haproxyEnabled }}
  {{- $host = printf "%s-redis-ha.%s.svc.cluster.local" .Release.Name .Release.Namespace -}}
{{- end }}
{{- if and $tlsEnabled (ne $externalHostname "") }}
  {{- $host = $externalHostname -}}
{{- end }}
{{- printf "%s://%s:%v" $scheme $host $port -}}
{{- end }}

{{/*
Database port helper: returns the configured database port from env.
Note: APP_DATABASE__PORT is required by deployment.yaml; this helper
assumes the value exists and does not provide a default.
*/}}
{{- define "status-list-server-chart.dbPort" -}}
{{- $env := .Values.statuslist.env | default dict }}
{{- get $env "APP_DATABASE__PORT" }}
{{- end }}
