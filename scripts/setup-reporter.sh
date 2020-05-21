#!/bin/bash
set -e

# apparently apt breaks if you don't do this... don't ask me
sleep 5

# install necessary packages
sudo apt update
sudo apt install -y golang-go jq docker.io

# add self to docker group
sudo usermod -aG docker $(whoami)

# get github's host keys, so that git clone will work
ssh-keyscan github.com >> ~/.ssh/known_hosts

git clone git@github.com:kelda-inc/blimp
cd blimp

echo -e "PATH=/usr/bin:/bin:/usr/local/bin\n*/5 * * * * (git -C ${PWD} pull && ${PWD}/scripts/integration-report.sh) >> ${HOME}/cron-log 2>&1" | crontab
