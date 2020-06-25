#!/bin/bash
set -euo pipefail

# this script is blimp/scripts/integration-report.sh
# cd to blimp
cd $(dirname "${BASH_SOURCE[0]}")/..

# install the latest version of blimp
# we can't use kelda.io/get-blimp.sh (install.sh) because
# it is interactive
# assume the latest tag is also the latest release
RELEASE=$(git describe --tags $(git rev-list --tags='*.*.*' --max-count=1))
ENDPOINT="https://blimp-releases.s3-us-west-1.amazonaws.com/blimp-linux-${RELEASE}"
curl -fsSLo blimp "$ENDPOINT"
chmod +x ./blimp
sudo mv ./blimp /usr/local/bin

# check that blimp is installed
which blimp

# do some cleanup
# blimp down might fail, but that's ok
blimp down || true
rm -rf ~/.blimp

# log in
blimp loginpw $(cat ~/blimp-creds)

# pull the latest node-todo
export GOPATH=~/go
app_location="$GOPATH/src/github.com/kelda/node-todo"
mkdir -p "$app_location"
rm -rf "$app_location"
git clone https://github.com/kelda/node-todo "$app_location"

# run the integration test
git checkout "${RELEASE}"
go test -v -tags ci -timeout 4m -run '^TestBlimp/NodeTodoDockerfile$' -count=1 ./ci
