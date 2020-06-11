#!/bin/bash
set -e

desired_path="$1"

mkdir -p certs

# Write the cert in the environment variable if it exists.
if [[ -n "${MANAGER_CERT_BASE64}" ]] ; then
	base64 -d <<< "${MANAGER_CERT_BASE64}" > "${desired_path}"
	exit 0
fi

# Otherwise, fallback to loading the cert from the manager repo.
local_cert_path="${GOPATH}/src/github.com/kelda-inc/blimp/certs/cluster-manager.crt.pem"
if [[ -f "${local_cert_path}" ]]; then
	ln -s "${local_cert_path}" "${desired_path}"
	exit 0
fi

echo "Cert not found. Aborting."
exit 1
