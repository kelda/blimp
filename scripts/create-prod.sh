#!/bin/bash
set -e

# This script should be invoked from the root of the Kelda Blimp repo.

PROJECT="kelda-blimp"

function _gcloud_kube() {
    gcloud container clusters --project "${PROJECT}" --zone us-west1-a $@
}

gcloud compute addresses --project kelda-blimp create registry --region us-west1
gcloud compute addresses --project kelda-blimp create manager --region us-west1
gcloud compute addresses --project kelda-blimp create login-proxy --region us-west1

# TODO: We actually run with a n1-standard-8 and n1-standard-16.
# TODO: Automate our fix of fixing nodemon by running `sudo sysctl fs.inotify.max_user_watches=1048576` on each kubelet node.
_gcloud_kube create customer -m e2-standard-2 --num-nodes=2 --no-enable-autoupgrade --enable-network-policy --image-type=ubuntu
_gcloud_kube get-credentials customer
./scripts/make-kubeconfig.sh > /tmp/customer-cluster-kubeconfig

_gcloud_kube create manager -m e2-standard-2 --num-nodes=1 --no-enable-autoupgrade
_gcloud_kube get-credentials manager
kubectl create secret -n manager generic customer-cluster-kubeconfig --from-file=config=/tmp/customer-cluster-kubeconfig
kubectl create secret -n manager generic manager-secrets --from-file=cert.pem=/Users/kevin/Google\ Drive/blimp-manager-certs/cluster-manager.crt.pem,key.pem=/Users/kevin/Google\ Drive/blimp-manager-certs/cluster-manager.key.pem,license=/Users/kevin/Google\ Drive/blimp-license/hosted-license
kubectl apply -f ./cluster-controller/kube

kubectl create namespace login-proxy
kubectl create secret -n login-proxy generic oauth-client-secret --from-env-file=/Users/kevin/Google\ Drive/auth0-client-secret.env

echo "Deployed the customer and manager clusters. Run 'kubectl get services' to get the manager's public IP."
