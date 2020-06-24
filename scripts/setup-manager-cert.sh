#!/bin/bash
set -e

# Must be invoked from the root of the repo.

desired_path="$1"

mkdir -p certs

# Write the cert from the local manager repo if it exists.
local_cert_path="${GOPATH}/src/github.com/kelda-inc/blimp/certs/cluster-manager.crt.pem"
if [[ -f "${local_cert_path}" ]]; then
	ln -s "${local_cert_path}" "${desired_path}"
	exit 0
fi

# Otherwise, fallback to using the production cert.
ln -s ../scripts/cluster-manager.crt.pem "${desired_path}"
