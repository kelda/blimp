# Installation

Make sure you're using go v1.13 or above.

1. Boot a Kubernetes cluster.
1. Generate credentials for the cluster-controller to deploy to the cluster. Use `./scripts/make-kubeconfig.sh` to generate a Kubeconfig.
1. Add the credentials to `cluster-controller/main.go`. Copy the relevant fields out of the Kubeconfig.
1. Add the BLIMP_DOCKER_REPO environment variable to your bashrc to configure builds to push to your dev registry.
1. Build the `sandbox-controller`: `make push-docker`.
1. Start the `cluster-controller`: `make run-cluster-controller`. This takes a while (couple minutes).
1. Compile the CLI: `go install ./cli`
1. Run `cli login`
1. Start the CLI, and point it to the local `cluster-controller`: `cd demo && MANAGER_HOST=localhost:9000 cli up` (the CLI always tries to deploy the `docker-compose.yml` in the current directory).
1. Make sure it works by accessing `localhost:8080` and hitting the node frontend. You'll know when it's ready when it says "Starting tunnel".

# Protobufs

Protobuf/grpc definitions are in `_proto`. Generate the corresponding Go files with `make generate`.
