#!/bin/bash
set -e

# apparently apt breaks if you don't do this... don't ask me
sleep 5

# install necessary packages
sudo apt update
sudo apt install -y golang-go jq docker.io make
sudo snap install kubectl --classic

# add self to docker group
sudo usermod -aG docker $(whoami)

# get github's host keys, so that git clone will work
ssh-keyscan github.com >> ~/.ssh/known_hosts

# setup the production monitor.
mkdir -p ~/prod-go/src/github.com/kelda-inc
cd ~/prod-go/src/github.com/kelda-inc
git clone git@github.com:kelda-inc/blimp
cd blimp
echo -e "PATH=/usr/bin:/bin:/usr/local/bin\n*/5 * * * * (git -C ${PWD} fetch --force --all --tags && ${PWD}/scripts/integration-reporter/integration-report.sh ${PWD}/scripts/integration-reporter/prod-integration-test.sh blimp.integration) >> ${HOME}/prod-cron-log 2>&1" | crontab

# setup the staging tests.
mkdir -p ~/staging-go/src/github.com/kelda-inc
cd ~/staging-go/src/github.com/kelda-inc
git clone git@github.com:kelda-inc/blimp
cd blimp
echo -e "PATH=/usr/bin:/bin:/usr/local/bin\n0 * * * * (git -C ${PWD} fetch --force --all && git -C ${PWD} reset --hard origin/master && ${PWD}/scripts/integration-reporter/integration-report.sh ${PWD}/scripts/integration-reporter/staging-integration-test.sh blimp.integration-staging) >> ${HOME}/staging-cron-log 2>&1" | crontab

echo "WARNING: INSTALLATION NOT COMPLETE"
echo "You still need to manually add the Kube credentials for the staging cluster to ~/.kube/config. Generate them with scripts/make-kubeconfig.sh"
