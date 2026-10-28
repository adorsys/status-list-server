#!/usr/bin/env bash
set -euo pipefail

# Adds test-only audience and issuer-registry values: the chart has no defaults, so deployments must choose their own.
helm() {
  local action="$1"
  shift
  if [[ "$action" == template || "$action" == lint ]]; then
    command helm "$action" --set-string statuslist.env.APP_MANAGEMENT_AUTH__AUDIENCES=https://helm-ci.invalid/api/v1 --set statuslist.issuerRegistry.volume.configMap.name=helm-ci-issuers "$@"
  else
    command helm "$action" "$@"
  fi
}
export RENDER_TEMP="${RENDER_TEMP:-/tmp}"
CHART_DIR="deploy/helm/chart"
mkdir -p "${RENDER_TEMP}/rendered"
CHART_APP_VERSION=$(helm show chart "$CHART_DIR" | sed -nE 's/^appVersion:[[:space:]]*"?([^"]+)"?[[:space:]]*$/\1/p')
CHART_BASE_VERSION="${CHART_APP_VERSION%-fscert}"
EXPECTED_AWS_TAG="${CHART_BASE_VERSION}-aws"
helm lint "$CHART_DIR"
helm lint "$CHART_DIR" -f "$CHART_DIR"/values-aws.yaml
helm lint "$CHART_DIR" -f "$CHART_DIR"/values-external-secrets.yaml
helm lint "$CHART_DIR" -f "$CHART_DIR"/values-aws.yaml -f "$CHART_DIR"/values-production.yaml
helm template status-list-server "$CHART_DIR" -f "$CHART_DIR"/values.yaml --output-dir "${RENDER_TEMP}/rendered/default"
helm template status-list-server "$CHART_DIR" -f "$CHART_DIR"/values-local.yaml --output-dir "${RENDER_TEMP}/rendered/local"
helm template status-list-server "$CHART_DIR" -f "$CHART_DIR"/values-external-secrets.yaml --output-dir "${RENDER_TEMP}/rendered/external-secrets"
helm template status-list-server "$CHART_DIR" -f "$CHART_DIR"/values-rotation-example.yaml --output-dir "${RENDER_TEMP}/rendered/rotation"
helm template status-list-server "$CHART_DIR" --set serviceAccount.create=false --output-dir "${RENDER_TEMP}/rendered/no-sa"
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=aws \
  --set statuslist.aws.mountCredentials=true \
  --output-dir "${RENDER_TEMP}/rendered/legacy-creds"
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=vault \
  --set secretStore.vault.server=https://vault.example.com \
  --output-dir "${RENDER_TEMP}/rendered/vault"
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=gcp \
  --set secretStore.gcp.projectID=my-project-id \
  --output-dir "${RENDER_TEMP}/rendered/gcp"
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=gcp \
  --set secretStore.gcp.projectID=my-project-id \
  --set-string 'externalSecret.spec.data[0].secretKey=postgres_password' \
  --set-string 'externalSecret.spec.data[0].remoteRef.key=statuslist-database-password' \
  --set-string 'externalSecret.spec.data[0].remoteRef.version=latest' \
  --set-string 'externalSecret.spec.data[0].remoteRef.decodingStrategy=None' \
  --set-string 'externalSecret.spec.data[0].remoteRef.conversionStrategy=Default' \
  --output-dir "${RENDER_TEMP}/rendered/gcp-remote-ref"
GCP_PASSWORD_FETCHES=$(grep -c 'key: statuslist-database-password' "${RENDER_TEMP}/rendered/gcp-remote-ref/status-list-server/templates/external-secrets.yaml" || true)
if [ "$GCP_PASSWORD_FETCHES" -ne 1 ]; then
  echo "ERROR: GCP ExternalSecret must fetch the database password once and template both Kubernetes Secret keys"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=azure \
  --set secretStore.azure.authType=WorkloadIdentity \
  --set secretStore.azure.serviceAccountRef.name=eso-controller-sa \
  --set secretStore.azure.tenantId=00000000-0000-0000-0000-000000000000 \
  --set secretStore.azure.vaultUrl=https://example.vault.azure.net \
  --output-dir "${RENDER_TEMP}/rendered/azure"
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=raw \
  --set-string 'secretStore.raw.webhook.severity=high' \
  --output-dir "${RENDER_TEMP}/rendered/raw"
if grep -qE '^\s{4}provider:\s*$' "${RENDER_TEMP}/rendered/raw/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: raw render must place the provider body directly under spec.provider (found nested provider under provider)"; exit 1
fi
if ! grep -qE '^\s{4}webhook:' "${RENDER_TEMP}/rendered/raw/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: raw render missing webhook provider from secretStore.raw"; exit 1
fi
helm template status-list-server "$CHART_DIR" -f "$CHART_DIR"/values-aws.yaml --output-dir "${RENDER_TEMP}/rendered/aws"
if ! grep -q "image: \"ghcr.io/adorsys/status-list-server:${EXPECTED_AWS_TAG}\"" "${RENDER_TEMP}/rendered/aws/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: AWS overlay must derive the AWS image variant from chart appVersion"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set postgres.enabled=false \
  --set statuslist.env.APP_DATABASE__BACKEND=mysql \
  --set statuslist.env.APP_DATABASE__HOST=mysql.example.internal \
  --set statuslist.networkPolicy.enabled=true \
  --set statuslist.networkPolicy.databaseEgress[0].podSelector.matchLabels.app\\.kubernetes\\.io/name=external-mysql \
  --set statuslist.image.repository=example.com/status-list-server \
  --set statuslist.image.tag=mysql \
  --output-dir "${RENDER_TEMP}/rendered/mysql"
if ! grep -q 'until nc -z mysql.example.internal 3306; do' "${RENDER_TEMP}/rendered/mysql/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: MySQL render must use the explicit database host and default MySQL port"; exit 1
fi
if ! grep -q 'key: postgres-password' "${RENDER_TEMP}/rendered/mysql/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: MySQL render must preserve the configured database password Secret key"; exit 1
fi
if ! grep -q 'app.kubernetes.io/name: external-mysql' "${RENDER_TEMP}/rendered/mysql/status-list-server/templates/network-policy.yaml"; then
  echo "ERROR: MySQL NetworkPolicy render must use statuslist.networkPolicy.databaseEgress"; exit 1
fi
if ! grep -q 'value: "3306"' "${RENDER_TEMP}/rendered/mysql/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: MySQL render must default APP_DATABASE__PORT from mysql.service.port"; exit 1
fi
if grep -q 'service.beta.kubernetes.io/aws-load-balancer' "${RENDER_TEMP}/rendered/aws/status-list-server/templates/service.yaml"; then
  echo "ERROR: AWS ingress overlay must not render direct AWS load balancer annotations"; exit 1
fi
if [ ! -f "${RENDER_TEMP}/rendered/aws/status-list-server/templates/ingress.yaml" ]; then
  echo "ERROR: AWS ingress overlay must render Ingress"; exit 1
fi
if ! grep -q '^  tls:' "${RENDER_TEMP}/rendered/aws/status-list-server/templates/ingress.yaml"; then
  echo "ERROR: AWS ingress overlay must render a tls block for cert-manager ingress-shim"; exit 1
fi
if [ ! -f "${RENDER_TEMP}/rendered/external-secrets/status-list-server/templates/external-secrets.yaml" ]; then
  echo "ERROR: values-external-secrets.yaml must render ExternalSecret resources"; exit 1
fi
if [ -f "${RENDER_TEMP}/rendered/external-secrets/status-list-server/templates/secret.yaml" ]; then
  echo "ERROR: values-external-secrets.yaml must disable fallback Secret"; exit 1
fi
helm template status-list-server "$CHART_DIR" -f "$CHART_DIR"/values-aws.yaml -f "$CHART_DIR"/values-aws-nlb.yaml --output-dir "${RENDER_TEMP}/rendered/aws-nlb"
if ! grep -q 'service.beta.kubernetes.io/aws-load-balancer-type' "${RENDER_TEMP}/rendered/aws-nlb/status-list-server/templates/service.yaml"; then
  echo "ERROR: AWS NLB overlay must render AWS load balancer annotations"; exit 1
fi
if [ -f "${RENDER_TEMP}/rendered/aws-nlb/status-list-server/templates/ingress.yaml" ]; then
  echo "ERROR: AWS NLB overlay must disable Ingress to avoid parallel public exposure"; exit 1
fi
if [ -f "${RENDER_TEMP}/rendered/default/status-list-server/templates/secret-store.yaml" ]; then
  echo "ERROR: default render must not produce a SecretStore"; exit 1
fi
if [ -f "${RENDER_TEMP}/rendered/default/status-list-server/templates/external-secrets.yaml" ]; then
  echo "ERROR: default render must not produce an ExternalSecret"; exit 1
fi
if grep -q 'service.beta.kubernetes.io/aws-load-balancer' "${RENDER_TEMP}/rendered/default/status-list-server/templates/service.yaml"; then
  echo "ERROR: default render must not include AWS Service annotations"; exit 1
fi
if grep -qE 'cert-manager.io/cluster-issuer|nginx.ingress.kubernetes.io/(force-)?ssl-redirect' "${RENDER_TEMP}/rendered/default/status-list-server/templates/ingress.yaml"; then
  echo "ERROR: default localhost Ingress must not force TLS or request cert-manager without tls hosts"; exit 1
fi
if grep -q '^  tls:' "${RENDER_TEMP}/rendered/default/status-list-server/templates/ingress.yaml"; then
  echo "ERROR: default localhost Ingress must not render a tls block"; exit 1
fi
helm template status-list-server "$CHART_DIR" --set-string statuslist.ingress.tls.secretName=statuslist-tls --output-dir "${RENDER_TEMP}/rendered/tls-secret-default-host"
if ! grep -q '^  tls:' "${RENDER_TEMP}/rendered/tls-secret-default-host/status-list-server/templates/ingress.yaml"; then
  echo "ERROR: explicit ingress TLS secretName must render a tls block even when tls.hosts is empty"; exit 1
fi
if ! grep -q '    - "localhost"' "${RENDER_TEMP}/rendered/tls-secret-default-host/status-list-server/templates/ingress.yaml"; then
  echo "ERROR: explicit ingress TLS secretName must default tls.hosts to the rendered ingress host"; exit 1
fi
if grep -qE 'APP_SERVER__CERT__(EMAIL|ORGANIZATION)' "${RENDER_TEMP}/rendered/default/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: default render must not inject blank certificate identity env vars"; exit 1
fi
if ! grep -q 'name: local-signing-material' "${RENDER_TEMP}/rendered/local/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: values-local.yaml must mount local signing material for the default fscert image"; exit 1
fi
if ! grep -q 'APP_SERVER__CERT__STORE__CERTIFICATE_PATH' "${RENDER_TEMP}/rendered/local/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: values-local.yaml must set APP_SERVER__CERT__STORE__CERTIFICATE_PATH"; exit 1
fi
if ! grep -q 'APP_SERVER__CERT__STORE__SIGNING_KEY_PATH' "${RENDER_TEMP}/rendered/local/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: values-local.yaml must set APP_SERVER__CERT__STORE__SIGNING_KEY_PATH"; exit 1
fi
if grep -q 'storageClassName:' "${RENDER_TEMP}/rendered/default/status-list-server/charts/postgres/templates/statefulset.yaml"; then
  echo "ERROR: default render must use the cluster default StorageClass"; exit 1
fi
if [ ! -f "${RENDER_TEMP}/rendered/default/status-list-server/templates/secret.yaml" ]; then
  echo "ERROR: default render must emit fallback statuslist-secret"; exit 1
fi
if ! grep -q 'name: statuslist-secret' "${RENDER_TEMP}/rendered/default/status-list-server/templates/secret.yaml"; then
  echo "ERROR: default fallback Secret must be named statuslist-secret"; exit 1
fi
if ! grep -q 'secretName: statuslist-secret' "${RENDER_TEMP}/rendered/default/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: default Deployment Secret volume must reference rendered statuslist-secret"; exit 1
fi
if ! grep -A3 'name: POSTGRES_PASSWORD' "${RENDER_TEMP}/rendered/default/status-list-server/charts/postgres/templates/statefulset.yaml" | grep -q 'name: statuslist-secret'; then
  echo "ERROR: default PostgreSQL POSTGRES_PASSWORD secretKeyRef must reference rendered statuslist-secret"; exit 1
fi
if ! grep -q 'name: statuslist-db-credentials' "${RENDER_TEMP}/rendered/rotation/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: rotation example must render the statuslist-db-credentials ExternalSecret"; exit 1
fi
if ! grep -q 'name: statuslist-api-keys' "${RENDER_TEMP}/rendered/rotation/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: rotation example must render the statuslist-api-keys ExternalSecret"; exit 1
fi
if [ -f "${RENDER_TEMP}/rendered/no-sa/status-list-server/templates/serviceaccount.yaml" ]; then
  echo "ERROR: serviceAccount.create=false must not render an application ServiceAccount"; exit 1
fi
if ! grep -q 'AWS_SHARED_CREDENTIALS_FILE' "${RENDER_TEMP}/rendered/legacy-creds/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: mountCredentials=true must render AWS_SHARED_CREDENTIALS_FILE"; exit 1
fi
if ! grep -q 'aws-credentials-volume' "${RENDER_TEMP}/rendered/legacy-creds/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: mountCredentials=true must render the aws-credentials-volume"; exit 1
fi
if ! grep -q 'name: statuslist-external-secret-aws-credentials' "${RENDER_TEMP}/rendered/legacy-creds/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: mountCredentials=true must render the aws-credentials ExternalSecret"; exit 1
fi
if ! grep -qE 'name: aws-credentials-secret' "${RENDER_TEMP}/rendered/legacy-creds/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: aws-credentials ExternalSecret must target aws-credentials-secret"; exit 1
fi
if ! grep -A2 'secretKey: credentials' "${RENDER_TEMP}/rendered/legacy-creds/status-list-server/templates/external-secrets.yaml" | grep -q 'remoteRef'; then
  echo "ERROR: aws-credentials ExternalSecret missing credentials remoteRef"; exit 1
fi
if ! grep -A2 'secretKey: config' "${RENDER_TEMP}/rendered/legacy-creds/status-list-server/templates/external-secrets.yaml" | grep -q 'remoteRef'; then
  echo "ERROR: aws-credentials ExternalSecret missing config remoteRef"; exit 1
fi
if ! grep -qE '^\s+vault:' "${RENDER_TEMP}/rendered/vault/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: vault provider SecretStore missing vault block"; exit 1
fi
if ! grep -qE '^\s+gcpsm:' "${RENDER_TEMP}/rendered/gcp/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: gcp provider SecretStore missing gcpsm block"; exit 1
fi
if ! grep -q 'version: latest' "${RENDER_TEMP}/rendered/gcp-remote-ref/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: ExternalSecret remoteRef.version must be rendered"; exit 1
fi
if ! grep -q 'decodingStrategy: None' "${RENDER_TEMP}/rendered/gcp-remote-ref/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: ExternalSecret remoteRef.decodingStrategy must be rendered"; exit 1
fi
if ! grep -q 'conversionStrategy: Default' "${RENDER_TEMP}/rendered/gcp-remote-ref/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: ExternalSecret remoteRef.conversionStrategy must be rendered"; exit 1
fi
if ! grep -qE '^\s+azurekv:' "${RENDER_TEMP}/rendered/azure/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: azure provider SecretStore missing azurekv block"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set-string 'statuslist.secretMounts[0].name=database-credentials' \
  --set-string 'statuslist.secretMounts[0].secretName=postgres-access' \
  --set-string 'statuslist.secretMounts[0].mountPath=/etc/secrets/database' \
  --set-string 'statuslist.secretMounts[0].fileEnv.APP_DATABASE__PASSWORD_FILE=password' \
  --output-dir "${RENDER_TEMP}/rendered/file-env-no-items"
if ! grep -q 'name: APP_DATABASE__PASSWORD_FILE' "${RENDER_TEMP}/rendered/file-env-no-items/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: fileEnv must render APP_DATABASE__PASSWORD_FILE"; exit 1
fi
if grep -q 'name: APP_DATABASE__PASSWORD$' "${RENDER_TEMP}/rendered/file-env-no-items/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: APP_DATABASE__PASSWORD must not render when APP_DATABASE__PASSWORD_FILE is configured"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
  --set-string 'statuslist.secretMounts[0].name=database-credentials' \
  --set-string 'statuslist.secretMounts[0].secretName=postgres-access' \
  --set-string 'statuslist.secretMounts[0].mountPath=/etc/secrets/database' \
  --set-string 'statuslist.secretMounts[0].items[0].key=password' \
  --set-string 'statuslist.secretMounts[0].items[0].path=password' \
  --set-string 'statuslist.secretMounts[0].fileEnv.APP_DATABASE__PASSWORD_FILE=pwd' \
  >"${RENDER_TEMP}/rendered/file-env-mismatch.out" 2>&1; then
  echo "ERROR: fileEnv must fail when it does not match a declared items path"; exit 1
fi
if ! grep -q 'references "pwd", but items mounts only: password' "${RENDER_TEMP}/rendered/file-env-mismatch.out"; then
  echo "ERROR: fileEnv mismatch failure did not explain the missing items path"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=false \
  --set statuslist.fallbackSecret.enabled=true \
  --set-string statuslist.fallbackSecret.stringData.postgres-password=x \
  --output-dir "${RENDER_TEMP}/rendered/fallback"
# HPA mode omits replicas, so use maxUnavailable to satisfy kube-linter's pdb-min-available.
helm template status-list-server "$CHART_DIR" \
  --set autoscaling.enabled=true \
  --set podDisruptionBudget.enabled=true \
  --set podDisruptionBudget.maxUnavailable=1 \
  --set podDisruptionBudget.minAvailable=null \
  --output-dir "${RENDER_TEMP}/rendered/scaling"
helm template status-list-server "$CHART_DIR" \
  --set serviceAccount.name=statuslist-app-sa \
  --set-string 'serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:aws:iam::123456789012:role/statuslist-irsa' \
  --set externalSecret.enabled=false \
  --set statuslist.fallbackSecret.enabled=true \
  --set-string statuslist.fallbackSecret.stringData.postgres-password=x \
  --output-dir "${RENDER_TEMP}/rendered/wl-app"
if ! grep -q 'name: statuslist-app-sa' "${RENDER_TEMP}/rendered/wl-app/status-list-server/templates/serviceaccount.yaml"; then
  echo "ERROR: workload-identity render missing application ServiceAccount statuslist-app-sa"; exit 1
fi
if ! grep -q 'eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/statuslist-irsa' "${RENDER_TEMP}/rendered/wl-app/status-list-server/templates/serviceaccount.yaml"; then
  echo "ERROR: workload-identity render missing IRSA role annotation"; exit 1
fi
if ! grep -q 'serviceAccountName: statuslist-app-sa' "${RENDER_TEMP}/rendered/wl-app/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: Deployment must reference application ServiceAccount statuslist-app-sa"; exit 1
fi
helm template status-list-server "$CHART_DIR" -f "$CHART_DIR"/values-aws.yaml -f "$CHART_DIR"/values-production.yaml \
  --output-dir "${RENDER_TEMP}/rendered/wl-prod"
if [ -f "${RENDER_TEMP}/rendered/wl-prod/status-list-server/templates/serviceaccount.yaml" ] && grep -q 'eks.amazonaws.com/role-arn:' "${RENDER_TEMP}/rendered/wl-prod/status-list-server/templates/serviceaccount.yaml"; then
  echo "ERROR: production AWS render must not render an IRSA role annotation (ESO-mounted production path)"; exit 1
fi
if ! grep -qE 'AWS_SHARED_CREDENTIALS_FILE|aws-credentials-volume' "${RENDER_TEMP}/rendered/wl-prod/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: production AWS render must mount the ESO-provisioned AWS credentials (mountCredentials=true production path)"; exit 1
fi
# Same overrides deploy.yml adds; the wl-prod render above can't catch a regression here.
helm template status-list-server "$CHART_DIR" \
  -f "$CHART_DIR"/values-aws.yaml \
  -f "$CHART_DIR"/values-production.yaml \
  --set-string "externalSecret.spec.secretStoreRef.name=datev-secret-store" \
  --set-string "externalSecret.spec.secretStoreRef.kind=ClusterSecretStore" \
  --set "secretStore.enabled=false" \
  --output-dir "${RENDER_TEMP}/rendered/prod-clusterstore"
if [ -f "${RENDER_TEMP}/rendered/prod-clusterstore/status-list-server/templates/secret-store.yaml" ]; then
  echo "ERROR: production render with secretStore.enabled=false must not emit a namespaced SecretStore"; exit 1
fi
if [ ! -f "${RENDER_TEMP}/rendered/prod-clusterstore/status-list-server/templates/external-secrets.yaml" ]; then
  echo "ERROR: production render must emit ExternalSecret resources"; exit 1
fi
PROD_ES_COUNT=$(grep -c 'kind: ExternalSecret' "${RENDER_TEMP}/rendered/prod-clusterstore/status-list-server/templates/external-secrets.yaml" || true)
if [ "$PROD_ES_COUNT" -lt 1 ]; then
  echo "ERROR: production render must emit at least one ExternalSecret"; exit 1
fi
PROD_STORE_REF_COUNT=$(grep -c 'name: datev-secret-store' "${RENDER_TEMP}/rendered/prod-clusterstore/status-list-server/templates/external-secrets.yaml" || true)
PROD_STORE_KIND_COUNT=$(grep -c 'kind: ClusterSecretStore' "${RENDER_TEMP}/rendered/prod-clusterstore/status-list-server/templates/external-secrets.yaml" || true)
if [ "$PROD_STORE_REF_COUNT" -ne "$PROD_ES_COUNT" ] || [ "$PROD_STORE_KIND_COUNT" -ne "$PROD_ES_COUNT" ]; then
  echo "ERROR: every production ExternalSecret must reference ClusterSecretStore/datev-secret-store (refs=$PROD_STORE_REF_COUNT kinds=$PROD_STORE_KIND_COUNT es=$PROD_ES_COUNT)"; exit 1
fi
# A secretEnv/ExternalSecret mismatch only shows at pod start; assert the cross-reference at render time.
PROD_ES="${RENDER_TEMP}/rendered/prod-clusterstore/status-list-server/templates/external-secrets.yaml"
PROD_DEPLOY="${RENDER_TEMP}/rendered/prod-clusterstore/status-list-server/templates/deployment.yaml"
REDIS_ES_BLOCK=$(awk 'BEGIN{RS="---\n"} /name: statuslist-redis-credentials/ {print}' "$PROD_ES")
if [ -z "$REDIS_ES_BLOCK" ]; then
  echo "ERROR: production render must emit the statuslist-redis-credentials ExternalSecret"; exit 1
fi
ES_TARGET_NAME=$(printf '%s\n' "$REDIS_ES_BLOCK" | awk '/^  target:/ {t=1; next} t && /^    name:/ {sub(/.*name: */, ""); gsub(/[" ]/, ""); print; exit} t && !/^    / {t=0}')
ES_SECRET_KEY=$(printf '%s\n' "$REDIS_ES_BLOCK" | grep -E '^\s+-?\s*secretKey:' | head -1 | sed 's/.*secretKey: //' | tr -d ' "')
DEPLOY_REF_NAME=$(grep -A4 'name: APP_CACHE__PASSWORD' "$PROD_DEPLOY" | grep -E 'name:' | tail -1 | sed 's/.*name: //' | tr -d ' "')
DEPLOY_REF_KEY=$(grep -A4 'name: APP_CACHE__PASSWORD' "$PROD_DEPLOY" | grep -E 'key:' | tail -1 | sed 's/.*key: //' | tr -d ' "')
if [ "$DEPLOY_REF_NAME" != "$ES_TARGET_NAME" ]; then
  echo "ERROR: APP_CACHE__PASSWORD secretKeyRef name '$DEPLOY_REF_NAME' does not match ExternalSecret target '$ES_TARGET_NAME'"; exit 1
fi
if [ "$DEPLOY_REF_KEY" != "$ES_SECRET_KEY" ]; then
  echo "ERROR: APP_CACHE__PASSWORD secretKeyRef key '$DEPLOY_REF_KEY' does not match ExternalSecret secretKey '$ES_SECRET_KEY'"; exit 1
fi

helm template status-list-server "$CHART_DIR" \
  --set serviceAccount.name=azure-app-sa \
  --set 'serviceAccount.annotations.azure\.workload\.identity/client-id=11111111-2222-3333-4444-555555555555' \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=azure \
  --set secretStore.azure.authType=WorkloadIdentity \
  --set secretStore.azure.serviceAccountRef.name=eso-controller-sa \
  --set secretStore.azure.tenantId=00000000-0000-0000-0000-000000000000 \
  --set secretStore.azure.vaultUrl=https://example.vault.azure.net \
  --set-string 'statuslist.podLabels.azure\.workload\.identity/use=true' \
  --output-dir "${RENDER_TEMP}/rendered/wl-azure"
if ! grep -qE 'azure\.workload\.identity/use:\s*"true"$' "${RENDER_TEMP}/rendered/wl-azure/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: Azure WI app pod label azure.workload.identity/use=\"true\" (string, not boolean) missing"; exit 1
fi
if ! grep -q 'azure.workload.identity/client-id: 11111111-2222-3333-4444-555555555555' "${RENDER_TEMP}/rendered/wl-azure/status-list-server/templates/serviceaccount.yaml"; then
  echo "ERROR: Azure WI app ServiceAccount missing azure.workload.identity/client-id annotation"; exit 1
fi
if ! grep -q 'serviceAccountName: azure-app-sa' "${RENDER_TEMP}/rendered/wl-azure/status-list-server/templates/deployment.yaml"; then
  echo "ERROR: Azure WI Deployment must reference application ServiceAccount azure-app-sa"; exit 1
fi
if [ "$(grep -A2 'serviceAccountRef:' "${RENDER_TEMP}/rendered/wl-azure/status-list-server/templates/secret-store.yaml" | grep 'name:' | head -1 | sed -E 's/.*name: ([^ ]+).*/\1/')" = "azure-app-sa" ]; then
  echo "ERROR: ESO serviceAccountRef must be distinct from the application ServiceAccount"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=azure \
  --set secretStore.azure.authType=ManagedIdentity \
  --set secretStore.azure.identityId=00000000-0000-0000-0000-000000000000 \
  --set secretStore.azure.tenantId=00000000-0000-0000-0000-000000000000 \
  --set secretStore.azure.vaultUrl=https://example.vault.azure.net \
  --output-dir "${RENDER_TEMP}/rendered/azure-mi"
if ! grep -qE '^\s+authType: "ManagedIdentity"' "${RENDER_TEMP}/rendered/azure-mi/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: Azure ManagedIdentity render missing authType=ManagedIdentity"; exit 1
fi
if ! grep -qE '^\s+identityId:' "${RENDER_TEMP}/rendered/azure-mi/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: Azure ManagedIdentity render missing identityId field"; exit 1
fi
if grep -qE 'serviceAccountRef:' "${RENDER_TEMP}/rendered/azure-mi/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: Azure ManagedIdentity render must not include serviceAccountRef"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=azure \
  --set secretStore.azure.authType=ServicePrincipal \
  --set secretStore.azure.tenantId=00000000-0000-0000-0000-000000000000 \
  --set secretStore.azure.vaultUrl=https://example.vault.azure.net \
  --set-string 'secretStore.azure.authSecretRef.clientId.name=azure-client-id' \
  --set-string 'secretStore.azure.authSecretRef.clientId.key=client-id' \
  --set-string 'secretStore.azure.authSecretRef.clientSecret.name=azure-client-secret' \
  --set-string 'secretStore.azure.authSecretRef.clientSecret.key=client-secret' \
  --output-dir "${RENDER_TEMP}/rendered/azure-sp"
if ! grep -qE '^\s+authType: "ServicePrincipal"' "${RENDER_TEMP}/rendered/azure-sp/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: Azure ServicePrincipal render missing authType=ServicePrincipal"; exit 1
fi
if ! grep -qE '^\s+authSecretRef:' "${RENDER_TEMP}/rendered/azure-sp/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: Azure ServicePrincipal render missing authSecretRef block"; exit 1
fi
if grep -qE 'serviceAccountRef:' "${RENDER_TEMP}/rendered/azure-sp/status-list-server/templates/secret-store.yaml"; then
  echo "ERROR: Azure ServicePrincipal render must not include serviceAccountRef"; exit 1
fi

if helm template status-list-server "$CHART_DIR" --set secretStore.provider=invalid >/dev/null 2>&1; then
  echo "ERROR: provider=invalid should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" --set secretStore.provider=raw >/dev/null 2>&1; then
  echo "ERROR: provider=raw with empty secretStore.raw should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" --set statuslist.service.type=ExternalName >/dev/null 2>&1; then
  echo "ERROR: statuslist.service.type=ExternalName should fail because the chart does not render ExternalName Services"; exit 1
fi
helm template status-list-server "$CHART_DIR" --set-string global.domain=Example.COM --output-dir "${RENDER_TEMP}/rendered/uppercase-domain"
if ! grep -q 'host: statuslist.example.com' "${RENDER_TEMP}/rendered/uppercase-domain/status-list-server/templates/ingress.yaml"; then
  echo "ERROR: mixed-case global.domain must render as a lowercase Ingress host"; exit 1
fi
if grep -q 'Example.COM' "${RENDER_TEMP}/rendered/uppercase-domain/status-list-server/templates/ingress.yaml"; then
  echo "ERROR: mixed-case global.domain must not render uppercase hostnames"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=true \
    --set secretStore.provider=vault >/dev/null 2>&1; then
  echo "ERROR: provider=vault with empty secretStore.vault.server should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=true \
    --set secretStore.provider=gcp >/dev/null 2>&1; then
  echo "ERROR: provider=gcp with empty secretStore.gcp.projectID should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=true \
    --set secretStore.provider=azure \
    --set secretStore.azure.authType=WorkloadIdentity \
    --set secretStore.azure.vaultUrl=https://example.vault.azure.net >/dev/null 2>&1; then
  echo "ERROR: provider=azure WorkloadIdentity without serviceAccountRef.name should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=true \
    --set secretStore.provider=azure \
    --set secretStore.azure.tenantId=00000000-0000-0000-0000-000000000000 \
    --set secretStore.azure.vaultUrl=https://example.vault.azure.net >/dev/null 2>&1; then
  echo "ERROR: provider=azure without identity configuration should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=true \
    --set secretStore.provider=azure \
    --set secretStore.azure.authType=ClientSecret \
    --set secretStore.azure.tenantId=t \
    --set secretStore.azure.vaultUrl=https://example.vault.azure.net >/dev/null 2>&1; then
  echo "ERROR: provider=azure with invalid authType=ClientSecret should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=false \
    --set secretStore.enabled=true 2>/dev/null | grep "kind: SecretStore" >/dev/null; then
  echo "ERROR: no-ESO mode must not render a SecretStore CR"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=false >/dev/null 2>&1; then
  echo "ERROR: externalSecret.enabled with secretStore.enabled=false should fail (dangling secretStoreRef)"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set autoscaling.enabled=true \
    --set autoscaling.minReplicas=5 \
    --set autoscaling.maxReplicas=2 >/dev/null 2>&1; then
  echo "ERROR: autoscaling.minReplicas > maxReplicas should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set podDisruptionBudget.enabled=true \
    --set podDisruptionBudget.minAvailable=1 \
    --set podDisruptionBudget.maxUnavailable=1 >/dev/null 2>&1; then
  echo "ERROR: PDB with both minAvailable and maxUnavailable should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set podDisruptionBudget.enabled=true \
    --set podDisruptionBudget.minAvailable=null \
    --set podDisruptionBudget.maxUnavailable=null >/dev/null 2>&1; then
  echo "ERROR: PDB with neither minAvailable nor maxUnavailable should fail"; exit 1
fi
# 0 is falsy in Go templates, so check it isn't dropped.
if ! helm template status-list-server "$CHART_DIR" \
    --set podDisruptionBudget.enabled=true \
    --set podDisruptionBudget.minAvailable=0 \
    --set podDisruptionBudget.maxUnavailable=null 2>/dev/null \
  | grep -E '^\s+minAvailable: 0$' >/dev/null; then
  echo "ERROR: PDB with minAvailable: 0 must render minAvailable: 0 (explicit zero preserved)"; exit 1
fi
if ! helm template status-list-server "$CHART_DIR" \
    --set podDisruptionBudget.enabled=true \
    --set podDisruptionBudget.minAvailable=null \
    --set podDisruptionBudget.maxUnavailable=0 2>/dev/null \
  | grep -E '^\s+maxUnavailable: 0$' >/dev/null; then
  echo "ERROR: PDB with maxUnavailable: 0 must render maxUnavailable: 0 (explicit zero preserved)"; exit 1
fi

REGION=$(helm template status-list-server "$CHART_DIR" \
  --set secretStore.provider=aws \
  --set secretStore.aws.region=us-west-2 \
  | grep -A1 'name: APP_AWS__REGION' | grep 'value:' | sed -E 's/.*value: "?([^"]*)"?.*/\1/' || true)
if [ "$REGION" != "us-west-2" ]; then
  echo "ERROR: APP_AWS__REGION should fall back to legacy secretStore.aws.region, got '$REGION'"; exit 1
fi
PGREF=$(helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=false \
    --set statuslist.fallbackSecret.enabled=true \
    --set-string statuslist.fallbackSecret.stringData.postgres-password=x 2>/dev/null \
  | grep -A3 'name: POSTGRES_PASSWORD' | grep 'name:' | tail -1 | sed -E 's/.*name: ([a-zA-Z0-9-]+)$/\1/')
if [ "$PGREF" != "statuslist-secret" ]; then
  echo "ERROR: POSTGRES_PASSWORD secretKeyRef must reference statuslist-secret, got '$PGREF'"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=true \
    --set secretStore.provider=aws \
    --set externalSecret.spec.target.name=custom-eso-secret >/dev/null 2>&1; then
  echo "ERROR: externalSecret.spec.target.name other than statuslist-secret should fail"; exit 1
fi
if ! helm template status-list-server "$CHART_DIR" \
    --set externalSecret.enabled=true \
    --set statuslist.fallbackSecret.enabled=false \
    --set secretStore.enabled=true \
    --set secretStore.provider=aws 2>/dev/null | grep -A1 '^  target:' | grep 'name: statuslist-secret' >/dev/null; then
  echo "ERROR: ExternalSecret target.name must be statuslist-secret"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set externalSecret.enabled=true \
  --set statuslist.fallbackSecret.enabled=false \
  --set secretStore.enabled=true \
  --set secretStore.provider=aws \
  --set-json 'externalSecret.spec.target.template.templateFrom=[{"configMap":{"name":"statuslist-secret-template","items":[{"key":"secret.tpl"}]}}]' \
  --output-dir "${RENDER_TEMP}/rendered/eso-template-from"
if ! grep -q 'templateFrom:' "${RENDER_TEMP}/rendered/eso-template-from/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: ExternalSecret target.template.templateFrom must render"; exit 1
fi
if ! grep -q 'database-password:' "${RENDER_TEMP}/rendered/eso-template-from/status-list-server/templates/external-secrets.yaml"; then
  echo "ERROR: ExternalSecret target.template.data must still emit database-password"; exit 1
fi
helm template status-list-server "$CHART_DIR" --set mysql.enabled=false --output-dir "${RENDER_TEMP}/rendered/mysql-disabled"
if helm template status-list-server "$CHART_DIR" \
    --set mysql.enabled=true >"${RENDER_TEMP}/rendered/mysql-enabled-fail.out" 2>&1; then
  echo "ERROR: mysql.enabled=true should fail because this chart does not vendor MySQL"; exit 1
fi
if ! grep -q 'mysql.enabled is not supported' "${RENDER_TEMP}/rendered/mysql-enabled-fail.out"; then
  echo "ERROR: mysql.enabled=true failure did not explain the unsupported bundled MySQL subchart"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set postgres.enabled=false \
    --set-string statuslist.env.APP_DATABASE__BACKEND=mysql \
    --set-string statuslist.image.tag=mysql >"${RENDER_TEMP}/rendered/mysql-missing-host-fail.out" 2>&1; then
  echo "ERROR: MySQL without APP_DATABASE__HOST should fail"; exit 1
fi
if ! grep -q 'statuslist.env.APP_DATABASE__HOST must be set' "${RENDER_TEMP}/rendered/mysql-missing-host-fail.out"; then
  echo "ERROR: MySQL missing-host failure did not explain APP_DATABASE__HOST"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set postgres.enabled=false \
    --set-string statuslist.env.APP_DATABASE__BACKEND=mysql \
    --set-string statuslist.env.APP_DATABASE__HOST=mysql.example.internal >"${RENDER_TEMP}/rendered/mysql-missing-image-fail.out" 2>&1; then
  echo "ERROR: MySQL without an explicit image tag or digest should fail"; exit 1
fi
if ! grep -q 'requires an explicit MySQL-capable image tag or digest' "${RENDER_TEMP}/rendered/mysql-missing-image-fail.out"; then
  echo "ERROR: MySQL missing-image failure did not explain tag or digest"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set-string statuslist.env.APP_DATABASE__BACKEND=sqlite >"${RENDER_TEMP}/rendered/sqlite-backend-fail.out" 2>&1; then
  echo "ERROR: sqlite backend should fail in the Helm chart"; exit 1
fi
if ! grep -q 'must be either postgres or mysql' "${RENDER_TEMP}/rendered/sqlite-backend-fail.out"; then
  echo "ERROR: sqlite backend failure did not explain supported Helm backends"; exit 1
fi
if helm template status-list-server "$CHART_DIR" 2>/dev/null | grep 'kind: NetworkPolicy' >/dev/null; then
  echo "ERROR: default render must NOT emit a NetworkPolicy (networkPolicy.enabled defaults to false)"; exit 1
fi
if ! helm template status-list-server "$CHART_DIR" \
    --set statuslist.networkPolicy.enabled=true 2>/dev/null \
  | grep -E 'app\.kubernetes\.io/name: postgres' >/dev/null; then
  echo "ERROR: NetworkPolicy egress must scope PostgreSQL to its pods (app.kubernetes.io/name: postgres)"; exit 1
fi
if ! helm template status-list-server "$CHART_DIR" \
    --set statuslist.networkPolicy.enabled=true 2>/dev/null \
  | grep -E '^\s+- podSelector:\s*$' >/dev/null; then
  echo "ERROR: NetworkPolicy egress internal rule must have a to:/podSelector (not any pod)"; exit 1
fi
NP=$(helm template status-list-server "$CHART_DIR" --set statuslist.networkPolicy.enabled=true 2>/dev/null)
if ! echo "$NP" | grep -E '^\s+- port: 8000\s*$' >/dev/null; then
  echo "ERROR: NetworkPolicy must allow the public port (8000)"; exit 1
fi
if echo "$NP" | grep -E '^\s+- port: (8001|8002)\s*$' >/dev/null; then
  echo "ERROR: NetworkPolicy must DENY management/admin by default (no rule for empty from:)"; exit 1
fi
NP_SCOPED=$(helm template status-list-server "$CHART_DIR" \
  --set statuslist.networkPolicy.enabled=true \
  --set 'statuslist.networkPolicy.managementIngress[0].namespaceSelector.matchLabels.kubernetes.io/metadata.name=ingress-nginx' \
  --set 'statuslist.networkPolicy.adminIngress[0].namespaceSelector.matchLabels.kubernetes.io/metadata.name=prometheus' 2>/dev/null)
if ! echo "$NP_SCOPED" | grep -E '^\s+- port: 8001\s*$' >/dev/null; then
  echo "ERROR: NetworkPolicy must allow management (8001) when managementIngress is set"; exit 1
fi
if ! echo "$NP_SCOPED" | grep -E '^\s+- port: 8002\s*$' >/dev/null; then
  echo "ERROR: NetworkPolicy must allow admin (8002) when adminIngress is set"; exit 1
fi

helm template status-list-server "$CHART_DIR" 2>/dev/null | awk '
  /^kind: Service$/{in_svc=1; svc=""; ports=""}
  in_svc && /^  name: /{svc=$2}
  in_svc && /^  - name: /{ports=ports " " $3}
  /^---$/{ if (in_svc && svc != "") { print svc ":" ports; } in_svc=0 }
' | while IFS= read -r line; do
  name=${line%%:*}
  ports=${line#*:}
  case "$name" in
    *-internal-service)
      for SVC_PORT in management admin; do
        if ! printf '%s\n' "$ports" | grep -qw "$SVC_PORT"; then
          echo "ERROR: internal Service must expose a ${SVC_PORT} port"; exit 1
        fi
      done
      ;;
    *-service)
      printf '%s\n' "$ports" | grep -qw "http" || { echo "ERROR: public Service must expose an http port"; exit 1; }
      if printf '%s\n' "$ports" | grep -qwE "management|admin"; then
        echo "ERROR: public Service must not expose management/admin"; exit 1
      fi
      ;;
  esac
done
if ! helm template status-list-server "$CHART_DIR" --set serviceMonitor.enabled=true 2>/dev/null | grep -A1 -E '^\s+- port: admin\s*$' | grep -q 'path: /metrics'; then
  echo "ERROR: ServiceMonitor must scrape the admin port at /metrics"; exit 1
fi
if ! helm template status-list-server "$CHART_DIR" 2>/dev/null | grep -B3 -A2 'path: /health/ready' | grep -q 'port: admin'; then
  echo "ERROR: readiness probe must target the admin port at /health/ready"; exit 1
fi
INGRESSES=$(helm template status-list-server "$CHART_DIR" --set statuslist.ingress.management.enabled=true 2>/dev/null \
  | awk '
    /^apiVersion: networking.k8s.io\/v1$/ { maybe=1; doc="" }
    maybe { doc = doc $0 "\n" }
    /^kind: Ingress$/ && maybe { capture=1 }
    /^---$/ { if (capture) { print doc; capture=0; maybe=0; doc="" } }
    END { if (capture) print doc }
  ')
if echo "$INGRESSES" | grep -E '^\s+number: 8002\s*$' >/dev/null; then
  echo "ERROR: Ingress must never reference the admin port (8002)"; exit 1
fi
MGMT_INGRESS=$(echo "$INGRESSES" | awk '/management-ingress/{f=1} f{print} f&&/^---$/{exit}')
if ! echo "$MGMT_INGRESS" | grep -qE '^\s+number: 8001\s*$'; then
  echo "ERROR: management Ingress backend must target the management port (8001)"; exit 1
fi

if ! helm template status-list-server "$CHART_DIR" --set statuslist.ingress.management.enabled=true 2>/dev/null \
    | awk '/management-ingress/{f=1} f{print} f&&/^---$/{exit}' | grep -q 'host: localhost'; then
  echo "ERROR: management Ingress must default to the shared public hostname"; exit 1
fi
if ! helm template status-list-server "$CHART_DIR" --set statuslist.ingress.management.enabled=true --set statuslist.ingress.management.hostname=mgmt.example.com 2>/dev/null \
    | awk '/management-ingress/{f=1} f{print} f&&/^---$/{exit}' | grep -q 'host: mgmt.example.com'; then
  echo "ERROR: management Ingress must honor a separate hostname"; exit 1
fi
MGMT_TLS=$(helm template status-list-server "$CHART_DIR" \
  --set statuslist.ingress.management.enabled=true \
  --set statuslist.ingress.management.hostname=mgmt.example.com \
  --set statuslist.ingress.tls.secretName=my-tls 2>/dev/null \
  | awk '/management-ingress/{f=1} f{print} f&&/^---$/{exit}')
if ! echo "$MGMT_TLS" | grep -q -- '- "mgmt.example.com"'; then
  echo "ERROR: management Ingress TLS hosts must target the management hostname"; exit 1
fi
if echo "$MGMT_TLS" | grep -q -- '- "localhost"'; then
  echo "ERROR: management Ingress must not reuse the public TLS host"; exit 1
fi
if ! echo "$MGMT_TLS" | grep -q 'external-dns.alpha.kubernetes.io/hostname: mgmt.example.com'; then
  echo "ERROR: management Ingress must emit an external-dns annotation for its separate hostname"; exit 1
fi
# ingress-nginx adds the leading ^ itself, so the path must start with "/".
# It must also be end-anchored, or a longer path could reach the management port.
MGMT_PATH=$(echo "$INGRESSES" | awk '/management-ingress/{f=1} f{print} f&&/^---$/{exit}' \
  | grep 'path:')
if ! echo "$MGMT_PATH" | grep -qE 'path:.*/api/v1/'; then
  echo "ERROR: management Ingress path must start with /api/v1/ (not ^)"; exit 1
fi
if ! echo "$MGMT_PATH" | grep -qE '\$"?[[:space:]]*$'; then
  echo "ERROR: management Ingress path must end with $ (anchored)"; exit 1
fi


# Render in a non-default namespace so a hard-coded matcher can't pass.
helm template status-list-server "$CHART_DIR" \
  --namespace statuslist-prod \
  --set externalSecret.enabled=false \
  --set statuslist.fallbackSecret.enabled=true \
  --set-string statuslist.fallbackSecret.stringData.postgres-password=x \
  --set prometheusRule.enabled=true \
  --output-dir "${RENDER_TEMP}/rendered/scoped-rules"
RULES="${RENDER_TEMP}/rendered/scoped-rules/status-list-server/templates/prometheusrule.yaml"
if ! grep -q 'otel_scope_name="status-list-server",namespace="statuslist-prod"' "$RULES"; then
  echo "ERROR: PrometheusRule raw selectors must be namespace-scoped"; exit 1
fi
if ! grep -q 'absent(up{namespace="statuslist-prod",service="status-list-server-service"})' "$RULES"; then
  echo "ERROR: StatusListMetricsAbsent must be namespace-scoped and select the rendered Service, not cluster-global"; exit 1
fi
if ! grep -q 'sli:error_budget:success:30d{namespace="statuslist-prod"}' "$RULES"; then
  echo "ERROR: recording-series reads in alert rules must be namespace-scoped"; exit 1
fi
ALERTS=$(grep -c -- '- alert:' "$RULES")
TEAMS=$(grep -c 'team: statuslist' "$RULES")
if [ "$ALERTS" -ne "$TEAMS" ]; then
  echo "ERROR: every alert must have team: statuslist ($TEAMS of $ALERTS alerts have it)"; exit 1
fi
if helm template status-list-server "$CHART_DIR" 2>/dev/null | grep -q 'kind: ConfigMap' \
    && helm template status-list-server "$CHART_DIR" 2>/dev/null | grep -q 'grafana_dashboard'; then
  echo "ERROR: default render must NOT emit the Grafana dashboard ConfigMap"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set grafanaDashboard.enabled=true \
  --output-dir "${RENDER_TEMP}/rendered/dashboard"
if [ ! -f "${RENDER_TEMP}/rendered/dashboard/status-list-server/templates/dashboard-configmap.yaml" ]; then
  echo "ERROR: grafanaDashboard.enabled=true must render dashboard-configmap.yaml"; exit 1
fi
if ! grep -q 'grafana_dashboard: "1"' "${RENDER_TEMP}/rendered/dashboard/status-list-server/templates/dashboard-configmap.yaml"; then
  echo "ERROR: dashboard ConfigMap must be labelled grafana_dashboard: \"1\""; exit 1
fi
if ! grep -q '"uid": "status-list-slo"' "${RENDER_TEMP}/rendered/dashboard/status-list-server/templates/dashboard-configmap.yaml"; then
  echo "ERROR: dashboard ConfigMap must embed the generated SLO dashboard JSON"; exit 1
fi
if helm template status-list-server "$CHART_DIR" 2>/dev/null | grep -q 'prometheus.io/scrape'; then
  echo "ERROR: default render must NOT emit prometheus.io/scrape Pod annotations"; exit 1
fi
helm template status-list-server "$CHART_DIR" \
  --set statuslist.prometheusAnnotations=true 2>/dev/null \
  | grep -q 'prometheus.io/scrape: "true"' \
  || { echo "ERROR: statuslist.prometheusAnnotations=true must render prometheus.io/scrape"; exit 1; }

if helm template status-list-server "$CHART_DIR" \
    --set alerting.enabled=true \
    --set alerting.platform=unsupported >/dev/null 2>&1; then
  echo "ERROR: alerting.enabled=true with unsupported platform should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set alerting.enabled=true \
    --set alerting.platform=slack >/dev/null 2>&1; then
  echo "ERROR: alerting.enabled=true with platform=slack and missing webhookUrl should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set alerting.enabled=true \
    --set alerting.platform=email \
    --set alerting.email.smtpHost=smtp.example.com \
    --set alerting.email.smtpFrom=alerts@example.com >/dev/null 2>&1; then
  echo "ERROR: alerting.platform=email with missing email.to should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set alerting.enabled=true \
    --set alerting.platform=email \
    --set alerting.email.to=ops@example.com \
    --set alerting.email.smtpFrom=alerts@example.com >/dev/null 2>&1; then
  echo "ERROR: alerting.platform=email with missing email.smtpHost should fail"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set alerting.enabled=true \
    --set alerting.platform=email \
    --set alerting.email.to=ops@example.com \
    --set alerting.email.smtpHost=smtp.example.com >/dev/null 2>&1; then
  echo "ERROR: alerting.platform=email with missing email.smtpFrom should fail"; exit 1
fi

helm template status-list-server "$CHART_DIR" \
  --set alerting.enabled=true \
  --set alerting.platform=slack \
  --set alerting.webhookUrl=https://hooks.slack.com/services/XXX \
  --output-dir "${RENDER_TEMP}/rendered/alerting-slack"
if [ ! -f "${RENDER_TEMP}/rendered/alerting-slack/status-list-server/templates/alertmanagerconfig.yaml" ]; then
  echo "ERROR: alerting.enabled=true must render AlertmanagerConfig"; exit 1
fi
if [ ! -f "${RENDER_TEMP}/rendered/alerting-slack/status-list-server/templates/alerting-secret.yaml" ]; then
  echo "ERROR: alerting.enabled=true without existingSecret must render Secret"; exit 1
fi

helm template status-list-server "$CHART_DIR" \
  --set alerting.enabled=true \
  --set alerting.platform=email \
  --set alerting.email.to=ops@example.com \
  --set alerting.email.smtpHost=smtp.example.com \
  --set-string alerting.email.smtpPort=587 \
  --set alerting.email.smtpFrom=alerts@example.com \
  --set alerting.email.smtpPassword=secretpw \
  --output-dir "${RENDER_TEMP}/rendered/alerting-email"
if ! grep -q 'smarthost: "smtp.example.com:587"' "${RENDER_TEMP}/rendered/alerting-email/status-list-server/templates/alertmanagerconfig.yaml"; then
  echo "ERROR: alerting.platform=email must render smarthost as host:port in AlertmanagerConfig"; exit 1
fi
if ! grep -q 'to: "ops@example.com"' "${RENDER_TEMP}/rendered/alerting-email/status-list-server/templates/alertmanagerconfig.yaml"; then
  echo "ERROR: alerting.platform=email must render `to` as a plain string in AlertmanagerConfig"; exit 1
fi
if ! grep -q 'smtp-password: "secretpw"' "${RENDER_TEMP}/rendered/alerting-email/status-list-server/templates/alerting-secret.yaml"; then
  echo "ERROR: alerting.platform=email must store the SMTP password in the Secret"; exit 1
fi
if grep -Eq 'email-to|smtp-host|smtp-from' "${RENDER_TEMP}/rendered/alerting-email/status-list-server/templates/alerting-secret.yaml"; then
  echo "ERROR: email to/smarthost/from must NOT be stored in the Secret (they are plain CRD strings)"; exit 1
fi
if helm template status-list-server "$CHART_DIR" \
    --set alerting.enabled=true \
    --set alerting.platform=email \
    --set alerting.email.to=ops@example.com \
    --set alerting.email.smtpHost=smtp.example.com \
    --set alerting.email.smtpFrom=alerts@example.com \
  | grep -q 'kind: Secret' && \
    helm template status-list-server "$CHART_DIR" \
    --set alerting.enabled=true \
    --set alerting.platform=email \
    --set alerting.email.to=ops@example.com \
    --set alerting.email.smtpHost=smtp.example.com \
    --set alerting.email.smtpFrom=alerts@example.com \
  | grep -q -- '-alerting'; then
  echo "ERROR: email without smtpPassword/dmsWebhookUrl must not render an empty alerting Secret"; exit 1
fi
