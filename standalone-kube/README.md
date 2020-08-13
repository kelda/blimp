# Self-hosted deployment

## Cert generation

Do this ONCE when you first set things up.

Run the `gen-certs.sh` script to generate certs. They will automatically be used
by the other scripts.

## Kubernetes deployment

Use the `./deploy.sh` script. You must provide as arguments:

- a docker repo that contains all the blimp system images
- the version of blimp you are deploying (should correspond to image tags,
  e.g. `0.13.21` or `latest`)
- the hostname used by the blimp registry. DNS for this hostname should point to
  the service created by `registry/registry-service.yaml`
- optionally, a kubectl context to use instead of the default

Run `./deploy.sh --help` to see usage.

You can run `./deploy.sh` whenever there is a new version to update, or to
redeploy if you make changes to the kubeyaml files directly.

## Blimp CLI config generation

To configure the blimp CLI to use the deployed self-hosted backend, run
`./gen-config.sh ~/.blimp/blimp.yaml`. As with `./deploy.sh`, you can also
optionally provide a kubectl context to use.

Distribute this `blimp.yaml` to anyone that you want to be able to access the
cluster.

You only need to re-run this if the manager service is recreated or if the certs
are regenerated.
