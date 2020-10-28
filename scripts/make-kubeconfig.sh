#!/bin/bash
set -euo pipefail

# Create the user.
kubectl create serviceaccount blimp-cluster-controller >/dev/null
kubectl create clusterrolebinding blimp-cluster-controller --clusterrole=cluster-admin --serviceaccount=default:blimp-cluster-controller >/dev/null

# Read the current settings.
context="$(kubectl config current-context)"
cluster="$(kubectl config view -o "jsonpath={.contexts[?(@.name==\"$context\")].context.cluster}")"
server="$(kubectl config view -o "jsonpath={.clusters[?(@.name==\"$cluster\")].cluster.server}")"
secret="$(kubectl get serviceaccount blimp-cluster-controller -o 'jsonpath={.secrets[0].name}' 2>/dev/null)"
ca_crt_data="$(kubectl get secret "$secret" -o "jsonpath={.data.ca\.crt}" | openssl enc -d -base64 -A)"
token="$(kubectl get secret "$secret" -o "jsonpath={.data.token}" | openssl enc -d -base64 -A)"

# Write them to a file.
export KUBECONFIG="$(mktemp)"
kubectl config set-credentials blimp-cluster-controller --token="$token" >/dev/null
ca_crt="$(mktemp)"; echo "$ca_crt_data" > $ca_crt
kubectl config set-cluster kelda-cluster --server="$server" --certificate-authority="$ca_crt" --embed-certs >/dev/null
kubectl config set-context kelda --cluster=kelda-cluster --user=blimp-cluster-controller>/dev/null
kubectl config use-context kelda >/dev/null

cat "$KUBECONFIG"
