#!/bin/sh
# Upload the release to S3. Called by Circle.
set -e

s3_bucket="blimp-releases"

# Create the release build.
VERSION=${CIRCLE_TAG} make build-cli-linux build-cli-osx build-cli-windows

linux_binary=blimp-linux-${CIRCLE_TAG}
osx_binary=blimp-osx-${CIRCLE_TAG}
windows_binary=blimp-windows-${CIRCLE_TAG}.exe
cp blimp-osx ${osx_binary}
cp blimp-linux ${linux_binary}
cp blimp-windows.exe ${windows_binary}
chmod +x ${osx_binary} ${linux_binary}

aws s3 cp ${osx_binary} s3://${s3_bucket}/${osx_binary} --acl public-read
aws s3 cp ${linux_binary} s3://${s3_bucket}/${linux_binary} --acl public-read
aws s3 cp ${windows_binary} s3://${s3_bucket}/${windows_binary} --acl public-read

# Upload the CLI image. push-docker rebuilds the linux binary, which fails if
# binary already exists.
rm blimp-linux
VERSION=${CIRCLE_TAG} make push-docker
