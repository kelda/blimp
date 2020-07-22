#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 LINK_PROXY_BASE_HOSTNAME LINK_PROXY_IP"
	exit 1
fi

PROJECT="kelda-blimp"
DOMAIN="$1"
PROXY_IP="$2"

gcloud --project "$PROJECT" dns managed-zones create blimp-dev --description="zone for $DOMAIN" --dns-name="$DOMAIN"
echo "Add these NS records for $DOMAIN:"
gcloud --project "$PROJECT" dns managed-zones describe blimp-dev | grep -A4 "nameServers:" | tail -4

gcloud --project "$PROJECT" dns record-sets transaction start --zone="blimp-dev"
gcloud --project "$PROJECT" dns record-sets transaction add --zone="blimp-dev" \
	--name="*.$DOMAIN" --ttl="600" --type="A" "$PROXY_IP"
gcloud --project "$PROJECT" dns record-sets transaction execute --zone="blimp-dev"
