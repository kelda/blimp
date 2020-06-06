#!/bin/bash
set -e

PROJECT="kelda-blimp"
ZONE="us-west1-a"
CLUSTER_NAME="customer"
nodes=$(gcloud compute instances list \
    --project="${PROJECT}" \
    --filter="metadata.items.key['cluster-name']['value']=${CLUSTER_NAME}" \
    --format="value(name)")

echo "Going to update the following nodes:"
echo "${nodes}"
echo
read -p "Hit enter to continue, or Ctrl-C to exit"

for node in ${nodes[@]}; do
	echo $node
	gcloud compute --project "${PROJECT}" ssh "$node" --zone "${ZONE}" --command "echo '{\"default-ulimits\":{\"memlock\":{\"Name\":\"memlock\",\"Hard\":-1,\"Soft\":-1}}}' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker"
done
