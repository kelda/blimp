#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || "$1" = "--help" ]]; then
	echo "usage: $0 OUTPUT [KUBECTL_CONTEXT]"
	exit 1
fi

output_file="$1"
kubectl_context=""
if [[ $# -eq 2 ]]; then
	kubectl_context="$2"
else
	kubectl_context="$(kubectl config current-context)"
fi

function _kubectl() {
	kubectl --context "$kubectl_context" "$@"
}

# Clear the config file if it exists before starting to write to it.
if [[ -f "$output_file" ]]; then
	rm "$output_file"
fi

kube_cluster="$(kubectl config view -o jsonpath='{.contexts[?(@.name == "'"${kubectl_context}"'")].context.cluster}')"
kube_host="$(kubectl config view -o jsonpath='{.clusters[?(@.name == "'"${kube_cluster}"'")].cluster.server}')"
echo "kube_host: \"${kube_host}\"" >> "$output_file"

manager_host="$(_kubectl -n manager get service manager -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
if [[ ! -n "$manager_host" ]]; then
	# This may be a DNS-based LB instead.
	manager_host="$(_kubectl -n manager get service manager -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')"
fi
echo "manager_host: \"${manager_host}:443\"" >> "$output_file"
echo "manager_cert: |" >> "$output_file"
# Indent the cert contents 4 spaces.
cat "$(dirname "$0")"/certs/manager.crt.pem | sed -e 's/^/    /' >> "$output_file"
