#!/bin/bash

NAMESPACE=default  # Change if your app is in a different namespace
APP_LABEL="app=status-list-server-chart"  # Adjust if your app label is different
DB_LABEL="app.kubernetes.io/name=postgresql"  # Adjust if your DB label is different

echo "Finding app pod..."
APP_POD=$(kubectl get pods -n $NAMESPACE -l $APP_LABEL -o jsonpath='{.items[0].metadata.name}')
echo "App pod: $APP_POD"

echo "Finding DB pod..."
DB_POD=$(kubectl get pods -n $NAMESPACE -l $DB_LABEL -o jsonpath='{.items[0].metadata.name}')
echo "DB pod: $DB_POD"

echo "---- App Pod Environment Variables ----"
kubectl exec -n $NAMESPACE $APP_POD -- printenv | grep -E 'DATABASE_URL|POSTGRES_'

echo "---- App Pod: Test DB Connectivity ----"
kubectl exec -n $NAMESPACE $APP_POD -- sh -c 'apt-get update && apt-get install -y postgresql-client || true'
kubectl exec -n $NAMESPACE $APP_POD -- sh -c 'psql "$DATABASE_URL" -c "\conninfo"' || echo "psql connection failed"

echo "---- DB Pod Status ----"
kubectl get pods -n $NAMESPACE -l $DB_LABEL

echo "---- DB Pod Logs (last 20 lines) ----"
kubectl logs -n $NAMESPACE $DB_POD | tail -20

echo "---- DB Service ----"
kubectl get svc -n $NAMESPACE | grep postgres

echo "---- Open Connections in DB ----"
kubectl exec -n $DB_POD -- psql -U postgres -d status-list -c "SELECT count(*) FROM pg_stat_activity;" || echo "Could not query DB"

echo "---- App Pod Logs (last 40 lines) ----"
kubectl logs -n $NAMESPACE $APP_POD | tail -40