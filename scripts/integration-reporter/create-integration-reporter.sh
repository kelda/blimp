#!/bin/bash
set -e

PROJECT="kelda-blimp"
INSTANCE="integration-reporter"
ZONE=us-west1-a

function _gcloud_compute() {
    gcloud compute --project "${PROJECT}" "$@"
}

if [[ $# -ne 2 ]]; then
	echo "usage: $0 path/to/id_ed25519 path/to/reporter-creds"
	echo "id_ed25519 is an ed25519 SSH key with access to kelda-inc/blimp"
	echo "reporter-creds are the arguments to blimp loginpw"
	echo "  (e.g. \"--username test@example.com --password p@ssw0rd\")"
	exit 1
fi

_gcloud_compute instances create "${INSTANCE}" --zone "${ZONE}" --machine-type n1-standard-1 --image-family=ubuntu-2004-lts --image-project=ubuntu-os-cloud --boot-disk-size=100GB

# wait for machine to come up
sleep 30

_gcloud_compute scp --zone "${ZONE}" "$1" reporter@"${INSTANCE}":.ssh/id_ed25519
_gcloud_compute scp --zone "${ZONE}" "$2" reporter@"${INSTANCE}":blimp-creds

setup_location=$(dirname "${BASH_SOURCE[0]}")/setup-reporter.sh
_gcloud_compute scp --zone "${ZONE}" "${setup_location}" reporter@"${INSTANCE}":setup.sh

_gcloud_compute ssh --zone "${ZONE}" reporter@"${INSTANCE}" --command="bash setup.sh"
