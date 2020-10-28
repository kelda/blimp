#!/bin/bash

# NOTE: Changes don't persist across restarts.

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
	gcloud compute --project "${PROJECT}" ssh "$node" --zone "${ZONE}" --command 'let quota=$(cat /sys/fs/cgroup/cpu/kubepods/cpu.cfs_period_us)*4 && printf ${quota} | sudo tee /sys/fs/cgroup/cpu/kubepods/cpu.cfs_quota_us'
done
