#!/bin/bash

set -e

# Usage: ./certbot_setup.sh yourdomain.com you@example.com

DOMAIN="$1"
EMAIL="$2"

if [ -z "$DOMAIN" ]; then
  echo "❌ Domain is required. Usage: ./certbot_setup.sh yourdomain.com [you@example.com]"
  exit 1
fi

if [ -z "$EMAIL" ]; then
  echo "ℹ️ No email provided. Using --register-unsafely-without-email"
  EMAIL_FLAG="--register-unsafely-without-email"
else
  EMAIL_FLAG="--email $EMAIL"
fi

ROOT_DIR=$(pwd)
CONFIG_DIR="$ROOT_DIR/certs/config"
WORK_DIR="$ROOT_DIR/certs/work"
LOGS_DIR="$ROOT_DIR/certs/logs"

mkdir -p "$CONFIG_DIR" "$WORK_DIR" "$LOGS_DIR"

certbot certonly \
  --standalone \
  --preferred-challenges http \
  $EMAIL_FLAG \
  --agree-tos \
  --no-eff-email \
  --config-dir "$CONFIG_DIR" \
  --work-dir "$WORK_DIR" \
  --logs-dir "$LOGS_DIR" \
  -d "$DOMAIN"

# Copy certificate and key to project root
CERT_PATH="$CONFIG_DIR/live/$DOMAIN"
cp "$CERT_PATH/fullchain.pem" "$ROOT_DIR/fullchain.pem"
cp "$CERT_PATH/privkey.pem" "$ROOT_DIR/privkey.pem"

echo "✅ Certificate and key have been copied to the project root."
