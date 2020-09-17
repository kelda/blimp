#!/bin/bash
set -euo pipefail

function pull_repo() {
    repo="$1"
    path="$2"

    # Pull the repo if it already exists. Clone it if it doesn't.
    if [ -d "${path}" ]; then
        git -C "${path}" fetch --all --force
        git -C "${path}" reset --hard origin/master
    else
        mkdir -p "$(dirname ${path})"
        git clone "${repo}" "${path}"
    fi
}

# this script is blimp/scripts/integration-reporter/integration-report.sh
# cd to blimp
cd $(dirname "${BASH_SOURCE[0]}")/../..

export GOPATH=~/staging-go

echo "Pulling latest versions of repos"
pull_repo git@github.com:kelda/blimp $GOPATH/src/github.com/kelda/blimp
pull_repo git@github.com:kelda/node-todo $GOPATH/src/github.com/kelda/node-todo

echo "Deploying new manager components"
./scripts/integration-reporter/update-staging.sh

echo "Configuring CLI repo"
pushd $GOPATH/src/github.com/kelda/blimp
# This needs to be done after deploying the manager so that it uses the
# generated manager certs.
make certs
cat <<EOF > local.mk
CLUSTER_MANAGER_HOST = 35.227.134.75:443
EOF
popd

go run ./ci/multirunner -concurrency 2
