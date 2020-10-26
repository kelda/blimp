#!/bin/bash
# This script should be run from the root of the Blimp repo.
# It assumes that the credentials for the Kubernetes cluster are on the
# machine, and that the default context points to the staging cluster.
set -euo pipefail

cat <<EOF > local.mk
DOCKER_REPO = gcr.io/kelda-blimp
VERSION = latest
REGISTRY_HOSTNAME = staging-blimp-registry.kelda.io
REGISTRY_IP = 34.83.60.95
REGISTRY_STORAGE = 20Gi
CLUSTER_MANAGER_IP = 35.227.134.75

# Unused by the tests, but we set it to real values so that the LetsEncrypt pod
# boots cleanly.
CLUSTER_MANAGER_HTTP_API_HOSTNAME = staging-blimp-manager-api.kelda.io
CLUSTER_MANAGER_HTTP_API_IP = 34.82.117.17
EOF

if ! kubectl get secret -n manager manager-certs > /dev/null; then
    make certs
	# Make sure the namespace exists.
	kubectl apply -f cluster-controller/kube/0_namespace.yaml
	kubectl create secret -n manager generic manager-certs \
		--from-file=cert.pem=certs/cluster-manager.crt.pem,key.pem=certs/cluster-manager.key.pem
fi

if ! kubectl get secret -n manager customer-cluster-kubeconfig > /dev/null; then
    kubectl create secret -n manager generic customer-cluster-kubeconfig --from-file=config=${HOME}/.kube/config
fi

# Deploy the manager service.
make deploy-manager

# Deploy the registry.
make deploy-registry

# Because the images use the floating `latest` tag, force the pods to redeploy.
# Delete the blimp-system namespace so that the manager recreates it.
kubectl delete --wait=true namespace blimp-system || true
kubectl rollout restart -n manager deployment/manager
kubectl rollout restart -n registry deployment/registry

# Wait for things to pods to restart.
kubectl rollout status -n manager deployment/manager --watch=true --timeout=10m
kubectl rollout status -n registry deployment/registry --watch=true --timeout=10m

# Wait for node controllers to deploy.
exp_node_controllers="$(kubectl get nodes -o name | wc -l)"
attempts=0
while true; do
    attempts=$((attempts + 1))
    if [[ ${attempts} -eq 24 ]]; then
        echo "Node controllers never booted"
        exit 1
    fi

    node_controllers="$(kubectl get pods -n blimp-system -o name --field-selector status.phase=Running)"
    if [[ $(wc -l <<< "${node_controllers}") == ${exp_node_controllers} ]]; then
        break
    fi

    echo "Node controllers not deployed yet"
    sleep 10
done

echo "Successfully updated cluster"
