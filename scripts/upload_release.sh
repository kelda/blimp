#!/bin/sh
# Upload the release to S3. Called by Circle.
set -e

s3_bucket="blimp-releases"

# Create the release build.
VERSION=${CIRCLE_TAG} make build-cli-linux build-cli-osx

linux_binary=blimp-linux-${CIRCLE_TAG}
osx_binary=blimp-osx-${CIRCLE_TAG}
cp blimp-osx ${osx_binary}
cp blimp-linux ${linux_binary}
chmod +x ${osx_binary} ${linux_binary}

aws s3 cp ${osx_binary} s3://${s3_bucket}/${osx_binary}
aws s3 cp ${linux_binary} s3://${s3_bucket}/${linux_binary}
