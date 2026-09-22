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
Effective name of the Kubernetes Secret the application reads (database password).
Single supported name: "statuslist-secret" in both ESO mode (ExternalSecret target) and
fallback mode. The Deployment volume, PostgreSQL (postgres.auth.existingSecret), and the
fallback Secret all reference this same name, so it is not independently configurable; ESO
mode validates externalSecret.spec.target.name against it at render time (external-secrets.yaml),
failing the release if changed. NOTE: statuslist.secretMounts is dynamic and may mount
arbitrary secret names — the default database-credentials entry in values.yaml happens to
reference this name, but that is an example, not a requirement of this helper.
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
Effective database backend for chart-managed defaults.
*/}}
{{- define "status-list-server-chart.dbBackend" -}}
{{- $env := .Values.statuslist.env | default dict }}
{{- get $env "APP_DATABASE__BACKEND" | default "postgres" }}
{{- end }}

{{/*
Default database password Secret item key. Explicit statuslist.secretMounts item
keys are preserved as written.
*/}}
{{- define "status-list-server-chart.databasePasswordSecretKey" -}}
{{- .Values.statuslist.database.passwordSecretKey | default "postgres-password" }}
{{- end }}

{{/*
Database host helper: returns the configured APP_DATABASE__HOST if set, otherwise the
default in-cluster service name for the active backend. For postgres it is
<release>-postgres.<namespace>.svc.cluster.local; for mysql the chart does not deploy a
Service, so an explicit APP_DATABASE__HOST is REQUIRED and the helper fails the render
otherwise.
*/}}
{{- define "status-list-server-chart.dbHost" -}}
{{- $env := .Values.statuslist.env | default dict }}
{{- $backend := include "status-list-server-chart.dbBackend" . }}
{{- if get $env "APP_DATABASE__HOST" }}
{{- get $env "APP_DATABASE__HOST" }}
{{- else if eq $backend "mysql" }}
{{- fail "statuslist.env.APP_DATABASE__HOST must be set when statuslist.env.APP_DATABASE__BACKEND=mysql because this chart does not deploy a MySQL Service" }}
{{- else if eq $backend "postgres" }}
{{- printf "%s-postgres.%s.svc.cluster.local" .Release.Name .Release.Namespace }}
{{- else }}
{{- fail (printf "statuslist.env.APP_DATABASE__BACKEND must be either postgres or mysql for this chart, got %q" $backend) }}
{{- end }}
{{- end }}

{{/*
Database port helper: returns the configured APP_DATABASE__PORT if set, otherwise the
active backend default (postgres.service.port / mysql.service.port). Used by the
wait-for-db init container and by the NetworkPolicy egress rule to scope internal egress
to the database port.
*/}}
{{- define "status-list-server-chart.dbPort" -}}
{{- $env := .Values.statuslist.env | default dict }}
{{- $backend := include "status-list-server-chart.dbBackend" . }}
{{- if get $env "APP_DATABASE__PORT" }}
{{- get $env "APP_DATABASE__PORT" }}
{{- else if eq $backend "mysql" }}
{{- .Values.mysql.service.port | toString }}
{{- else if eq $backend "postgres" }}
{{- .Values.postgres.service.port | toString }}
{{- else }}
{{- fail (printf "statuslist.env.APP_DATABASE__BACKEND must be either postgres or mysql for this chart, got %q" $backend) }}
{{- end }}
{{- end }}

{{/*
Database username helper: returns the configured username, or the active backend default.
*/}}
{{- define "status-list-server-chart.dbUsername" -}}
{{- $env := .Values.statuslist.env | default dict }}
{{- $backend := include "status-list-server-chart.dbBackend" . }}
{{- if get $env "APP_DATABASE__USERNAME" }}
{{- get $env "APP_DATABASE__USERNAME" }}
{{- else if eq $backend "mysql" }}
{{- .Values.mysql.auth.username }}
{{- else if eq $backend "postgres" }}
{{- .Values.postgres.auth.username }}
{{- else }}
{{- fail (printf "statuslist.env.APP_DATABASE__BACKEND must be either postgres or mysql for this chart, got %q" $backend) }}
{{- end }}
{{- end }}

{{/*
Database name helper: returns the configured database name, or the active backend default.
*/}}
{{- define "status-list-server-chart.dbName" -}}
{{- $env := .Values.statuslist.env | default dict }}
{{- $backend := include "status-list-server-chart.dbBackend" . }}
{{- if get $env "APP_DATABASE__NAME" }}
{{- get $env "APP_DATABASE__NAME" }}
{{- else if eq $backend "mysql" }}
{{- .Values.mysql.auth.database }}
{{- else if eq $backend "postgres" }}
{{- .Values.postgres.auth.database }}
{{- else }}
{{- fail (printf "statuslist.env.APP_DATABASE__BACKEND must be either postgres or mysql for this chart, got %q" $backend) }}
{{- end }}
{{- end }}
