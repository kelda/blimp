#!/bin/bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 || "$1" = "--help" ]]; then
	echo "usage: $0 DOCKER_REGISTRY VERSION REGISTRY_HOSTNAME [KUBECTL_CONTEXT]"
	exit 1
fi

image_registry="$1"
blimp_version="$2"
registry_hostname="$3"
kubectl_context=""
if [[ $# -eq 4 ]]; then
	kubectl_context="$4"
fi

function _kubectl() {
	if [[ -n "$kubectl_context" ]]; then
		kubectl --context "$kubectl_context" "$@"
	else
		kubectl "$@"
	fi
}

templates=()
function template() {
	file="$1"
	shift
	sed "$@" "${file}.tmpl" > "${file}"
	templates+=("$file")
}
function cleanup_templates() {
	for file in "${templates[@]}"; do
		rm "$file"
	done
}
trap cleanup_templates EXIT

cd "$(dirname "$0")"

## Manager
if _kubectl get secret -n manager manager-certs > /dev/null; then
	echo "Using manager certs already present in cluster."
elif [[ -f certs/manager.crt.pem && -f certs/manager.key.pem ]]; then
	# Make sure the namespace exists.
	_kubectl apply -f manager/0_namespace.yaml
	_kubectl create secret -n manager generic manager-certs \
		--from-file=cert.pem=certs/manager.crt.pem,key.pem=certs/manager.key.pem
else
	echo "Manager certs not found. Please generate certs (./gen-certs.sh) and try again."
	exit 1
fi

template manager/manager-deployment.yaml "s|<CLUSTER_MANAGER_IMAGE>|${image_registry}/blimp-cluster-controller:${blimp_version}|;s|<DOCKER_REPO>|${image_registry}|;s|<REGISTRY_HOSTNAME>|${registry_hostname}|"
_kubectl apply -f manager/

## Registry
template registry/registry-deployment.yaml "s|<REGISTRY_HOSTNAME>|${registry_hostname}|;s|<DOCKER_AUTH_IMAGE>|${image_registry}/blimp-docker-auth:${blimp_version}|"
_kubectl apply -f registry/
