#!/bin/bash
set -e

nodes=(
	gke-customer-pool-1-68ed6d5a-j6gm
	gke-customer-pool-1-68ed6d5a-kv4j
	gke-customer-pool-1-68ed6d5a-mldm
	gke-customer-pool-1-68ed6d5a-mxg1
	gke-customer-pool-1-68ed6d5a-nn3l
	gke-customer-pool-1-68ed6d5a-p4p2
	gke-customer-pool-1-68ed6d5a-s4lk
	gke-customer-pool-1-68ed6d5a-v9jp
)

for node in ${nodes[@]}; do
	echo $node
	gcloud compute --project kelda-blimp ssh "$node" --zone us-west1-a --command "echo '{\"default-ulimits\":{\"memlock\":{\"Name\":\"memlock\",\"Hard\":-1,\"Soft\":-1}}}' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker"
done
