#!/bin/bash
set -euo pipefail

# Create the clusterrole
kubectl create clusterrole blimp-link-proxy --verb=get --resource=pods,namespaces

# Create the user.
kubectl create serviceaccount blimp-link-proxy >/dev/null

# Create the clusterrole for pod/namespace access
kubectl create clusterrole blimp-link-proxy --verb=get --resource=pods,namespaces
kubectl create clusterrolebinding blimp-link-proxy --clusterrole=blimp-link-proxy --serviceaccount=default:blimp-link-proxy >/dev/null

# Create the role for node-controller cert access
kubectl -n blimp-system create role blimp-link-proxy-node-access --verb=get --resource=secrets
kubectl -n blimp-system create rolebinding blimp-link-proxy-node-access --role=blimp-link-proxy-node-access --serviceaccount=default:blimp-link-proxy >/dev/null

# Read the current settings.
context="$(kubectl config current-context)"
cluster="$(kubectl config view -o "jsonpath={.contexts[?(@.name==\"$context\")].context.cluster}")"
server="$(kubectl config view -o "jsonpath={.clusters[?(@.name==\"$cluster\")].cluster.server}")"
secret="$(kubectl get serviceaccount blimp-link-proxy -o 'jsonpath={.secrets[0].name}' 2>/dev/null)"
ca_crt_data="$(kubectl get secret "$secret" -o "jsonpath={.data.ca\.crt}" | openssl enc -d -base64 -A)"
token="$(kubectl get secret "$secret" -o "jsonpath={.data.token}" | openssl enc -d -base64 -A)"

# Write them to a file.
export KUBECONFIG="$(mktemp)"
kubectl config set-credentials blimp-link-proxy --token="$token" >/dev/null
ca_crt="$(mktemp)"; echo "$ca_crt_data" > $ca_crt
kubectl config set-cluster kelda-cluster --server="$server" --certificate-authority="$ca_crt" --embed-certs >/dev/null
kubectl config set-context kelda --cluster=kelda-cluster --user=blimp-link-proxy>/dev/null
kubectl config use-context kelda >/dev/null

cat "$KUBECONFIG"

rm "$KUBECONFIG"
