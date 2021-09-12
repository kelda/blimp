#!/bin/sh
# Builds the binaries. You will then need to manually upload these to a GitHub
# release and update install.sh. You can uncomment the docker build bit if you
# just want to build the CLI binaries.
set -e

# Create the release build.
VERSION=${CIRCLE_TAG} make build-cli-linux build-cli-osx build-cli-windows

linux_binary=blimp-linux-${CIRCLE_TAG}
osx_binary=blimp-osx-${CIRCLE_TAG}
windows_binary=blimp-windows-${CIRCLE_TAG}.exe
cp blimp-osx ${osx_binary}
cp blimp-linux ${linux_binary}
cp blimp-windows.exe ${windows_binary}
chmod +x ${osx_binary} ${linux_binary}

# Upload the CLI image. push-docker rebuilds the linux binary, which fails if
# binary already exists.
rm blimp-linux
VERSION=${CIRCLE_TAG} make push-docker
