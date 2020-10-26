#!/bin/bash
set -e

# This script should be invoked from the root of the Kelda Blimp repo.

version="$1"

if [[ -z ${version} ]]; then
    echo "Version is required"
    exit 1
fi

PROJECT="kelda-blimp"

function _gcloud_kube() {
    gcloud container clusters --project "${PROJECT}" --zone us-west1-a $@
}

curr_context="$(kubectl config current-context)"

_gcloud_kube get-credentials manager

# Set up the deployment configuration.
cat <<EOF > prod.mk
DOCKER_REPO = gcr.io/kelda-blimp
VERSION = ${version}
REGISTRY_HOSTNAME = blimp-registry.kelda.io
REGISTRY_IP = 35.203.163.180
REGISTRY_STORAGE = 500Gi
LOGIN_PROXY_HOSTNAME = blimp-login.kelda.io
LOGIN_PROXY_IP = 35.247.78.121
LOGIN_PROXY_GRPC_HOSTNAME = blimp-login-grpc.kelda.io
LINK_PROXY_IP = 34.83.205.18
LINK_PROXY_BASE_HOSTNAME = blimp.dev
CLUSTER_MANAGER_IP = 34.82.73.248
CLUSTER_MANAGER_HTTP_API_HOSTNAME = blimp-manager-api.kelda.io
CLUSTER_MANAGER_HTTP_API_IP = 35.247.75.232
EOF

# Deploy the manager service.
make deploy-manager

# Deploy the registry.
make deploy-registry

# Deploy the login proxy.
make deploy-login-proxy

# Deploy the link proxy.
make deploy-link-proxy

kubectl config use-context ${curr_context}