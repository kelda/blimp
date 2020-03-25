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

# TLS

The CLI communicates with the Cluster Manager and the Sandbox Controller over TLS.

The Cluster Manager certificate is pre-generated. The public key is
compiled into the CLI binary so that the CLI can verify against MITM attacks.
The private key is supplied to the Cluster Manager at runtime.

The Sandbox Controller public and private key is generated at runtime by the
Cluster Manager when a new development environment is created. The Cluster
Manager sends the Sandbox Controller's certificate to the CLI when `blimp up`
is run, again to avoid a MITM attack.

The certs for local development are stored in `./certs`. They are generated
with `make certs`, which is automatically run if certificates don't already
exist.

# Registry

The registry needs a DNS name, even during development. To deploy it:

1. Create a static IP address:

    ```
	gcloud compute addresses create registry --region us-west1
	gcloud compute addresses list
	```

1. Add an [A record](https://domains.google.com/m/registrar/kelda.io/dns) for
   the static IP to `dev-<your name>-blimp-registry.kelda.io`.

1. Create a `local.mk` file so that `make` deploys to your hostname.

    ```
    cat <<EOF > local.mk
    REGISTRY_HOSTNAME = dev-kevin-blimp-registry.kelda.io
    REGISTRY_IP = 34.83.86.50
    EOF
    ```

1. Deploy the registry with `make deploy-registry`

1. Running `make run-cluster-controller` will automatically cause your images
   to get pushed to the registry running in your cluster.
