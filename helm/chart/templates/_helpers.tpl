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
Shared shell script that syncs the HAProxy TLS secret (statuslist-haproxy-tls)
from the main wildcard certificate secret (statuslist-tls). Used by both the
post-install/post-upgrade bootstrap Job (immediate first sync) and the
periodic CronJob (renewal after cert-manager rotates the certificate).
*/}}
{{- define "status-list-server-chart.redisCertSyncScript" -}}
set -euo pipefail

NS="${NAMESPACE:-{{ .Release.Namespace }}}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Fetching base certificate from secret statuslist-tls in namespace ${NS}..."
kubectl get secret statuslist-tls -n "${NS}" -o jsonpath='{.data.tls\.crt}' | base64 -d > "${TMP_DIR}/tls.crt"
kubectl get secret statuslist-tls -n "${NS}" -o jsonpath='{.data.tls\.key}' | base64 -d > "${TMP_DIR}/tls.key"

cat "${TMP_DIR}/tls.crt" "${TMP_DIR}/tls.key" > "${TMP_DIR}/redis.pem"

# If the HAProxy secret exists, compare the current redis.pem with the new one.
if kubectl get secret statuslist-haproxy-tls -n "${NS}" >/dev/null 2>&1; then
  echo "Existing statuslist-haproxy-tls secret found, comparing redis.pem..."
  kubectl get secret statuslist-haproxy-tls -n "${NS}" -o jsonpath='{.data.redis\.pem}' | base64 -d > "${TMP_DIR}/existing-redis.pem" || true

  if [ -s "${TMP_DIR}/existing-redis.pem" ] && cmp -s "${TMP_DIR}/redis.pem" "${TMP_DIR}/existing-redis.pem"; then
    echo "Redis HAProxy certificate is already up to date. No changes applied."
    exit 0
  fi
else
  echo "statuslist-haproxy-tls secret does not exist yet. It will be created."
fi

echo "Applying updated statuslist-haproxy-tls secret..."
kubectl create secret generic statuslist-haproxy-tls \
  -n "${NS}" \
  --from-file=redis.pem="${TMP_DIR}/redis.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Redis HAProxy TLS secret synced successfully. Restarting HAProxy deployment to pick up new certificate..."
kubectl rollout restart deploy/{{ .Release.Name }}-redis-ha-haproxy -n "${NS}" 2>/dev/null || echo "HAProxy deployment not found yet, skipping restart (it will pick up the secret on its own startup)."

echo "Redis HAProxy deployment restart triggered."
{{- end }}

{{/*
Resolve the Redis connection URI based on chart values.
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
{{- printf "%s://:$(REDIS_PASSWORD)@%s:%v" $scheme $host $port -}}
{{- end }}
