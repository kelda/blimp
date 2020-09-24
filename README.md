# Creating a dev Kube cluster

You need a Kubernetes cluster for the customer containers to run in. In order
for GKE's network policy to work, you need at least two nodes in the cluster.

```
gcloud container clusters create dev -m n1-standard-2 --num-nodes=2 --no-enable-autoupgrade --enable-network-policy --image-type=ubuntu --preemptible
```

# Installation

Make sure you're using go v1.13 or above.

1. `make go-get`
1. Boot a Kubernetes cluster.
1. Make sure your current Kubernetes context is your dev cluster. That's where the `cluster-controller` will deploy the pods to.
1. Add the following to `local.mk`

    ```
    cat <<EOF > local.mk
    REGISTRY_HOSTNAME = dev-kevin-blimp-registry.kelda.io
    DOCKER_REPO = gcr.io/<your project>
    EOF
    ```

1. Build the `sandbox-controller`: `make push-docker`.
1. Start the `cluster-controller`: `make run-cluster-controller`.
1. Compile the CLI: `make install`
1. Run `cli login`
1. Point the CLI at your local `cluster-controller`: `export MANAGER_HOST=localhost:9000`
1. Boot an app. A good test is the node todo app.

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

# Running Integration Tests

The `./ci` directory contains a test that the local version of `blimp`.

It assumes that you've already authenticated with `blimp login`, and looks for
the repositories to test in your `$GOPATH`. Right now, it only tests
`github.com/kelda/node-todo`.

To run the tests, run `go test -v --tags ci -timeout=0 ./ci`.

# Updating Prod

1. Build new versions of the CLI and Docker images.

	```
	git tag 0.2.0
	git push upstream 0.2.0
	```

1. Deploy the latest images to the manager cluster.

	```
	./scripts/update-prod.sh <version>
	```

1. Update the install script to point to the new version in:

    * `blimpup.io/install-blimp.sh`. Make sure to update all AB tests.
    * `kelda/homebrew-kelda`
