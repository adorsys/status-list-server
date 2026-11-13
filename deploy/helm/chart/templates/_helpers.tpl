{{- define "status-list-server-chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Truncated to 63 chars, the DNS label limit; a release name that already holds the chart name is used as is. */}}
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

{{- define "status-list-server-chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "status-list-server-chart.labels" -}}
helm.sh/chart: {{ include "status-list-server-chart.chart" . }}
{{ include "status-list-server-chart.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "status-list-server-chart.selectorLabels" -}}
app: {{ include "status-list-server-chart.name" . }}
app.kubernetes.io/name: {{ include "status-list-server-chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Workload Identity trust is keyed on this name; renaming the SA breaks it. */}}
{{- define "status-list-server-chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "status-list-server-chart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Fixed: the Deployment, Postgres and the fallback Secret all use this name. */}}
{{- define "status-list-server-chart.appSecretName" -}}
{{- "statuslist-secret" }}
{{- end }}

{{/* statuslist.aws.region, else the legacy secretStore.aws.region; empty when neither is set. */}}
{{- define "status-list-server-chart.appRegion" -}}
{{- $r := .Values.statuslist.aws.region }}
{{- if not $r }}
{{- $r = .Values.secretStore.aws.region }}
{{- end }}
{{- $r }}
{{- end }}

{{/* Only postgres and mysql; anything else fails in the db* helpers below. */}}
{{- define "status-list-server-chart.dbBackend" -}}
{{- $env := .Values.statuslist.env | default dict }}
{{- get $env "APP_DATABASE__BACKEND" | default "postgres" }}
{{- end }}

{{/* Used only when a secretMounts item has no key. */}}
{{- define "status-list-server-chart.databasePasswordSecretKey" -}}
{{- .Values.statuslist.database.passwordSecretKey | default "postgres-password" }}
{{- end }}

{{/* MySQL needs an explicit APP_DATABASE__HOST; this chart doesn't deploy it. */}}
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
