#!/bin/bash
set -e

if [ -z "${BLIMP_TOKEN}" ]; then
	echo "BLIMP_TOKEN is required"
	exit 1
fi

if [ -z "${GIT_REPO}" ]; then
	echo "GIT_REPO is required"
	exit 1
fi


mkdir -p ~/.blimp
echo "AuthToken: ${BLIMP_TOKEN}" > ~/.blimp/auth.yaml

git clone "${GIT_REPO}" /app
cd /app

exec "$@"
