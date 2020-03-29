#!/bin/bash
set -e

# This script should be invoked from the root of the Kelda Blimp repo.

PROJECT="kelda-blimp"

function _gcloud_kube() {
    gcloud container clusters --project "${PROJECT}" --zone us-west1-a $@
}

gcloud compute addresses --project kelda-blimp create registry --region us-west1
gcloud compute addresses --project kelda-blimp create manager --region us-west1

_gcloud_kube create customer -m e2-standard-2 --num-nodes=2 --no-enable-autoupgrade
_gcloud_kube get-credentials customer
./scripts/make-kubeconfig.sh > /tmp/customer-cluster-kubeconfig

_gcloud_kube create manager -m e2-standard-2 --num-nodes=1 --no-enable-autoupgrade
_gcloud_kube get-credentials manager
kubectl create secret generic customer-cluster-kubeconfig --from-file=config=/tmp/customer-cluster-kubeconfig
kubectl apply -f ./cluster-controller/kube

echo "Deployed the customer and manager clusters. Run 'kubectl get services' to get the manager's public IP."
