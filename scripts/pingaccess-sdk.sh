#!/usr/bin/env bash
# Take the PingAccess Add-on SDK jar out of the public PingAccess image into .pa/lib and
# print its version. The SDK is on no Maven repository. The image is public and needs no
# licence to pull — only running it does. The jar's version is whatever the image ships,
# so it is read rather than assumed. Run from gateways/pingaccess/authzen-pdp; in GitHub
# Actions the version also lands in $GITHUB_ENV as PA_SDK_VERSION.
set -euo pipefail

image="${PA_IMAGE:-pingidentity/pingaccess:9.1.0-latest}"
jar=$(docker run --rm --entrypoint sh "$image" -c 'ls /opt/server/lib/pingaccess-sdk-*.jar')
version=$(basename "$jar" .jar | sed 's/^pingaccess-sdk-//')
id=$(docker create "$image")
trap 'docker rm "$id" >/dev/null' EXIT
mkdir -p .pa/lib
docker cp "$id:$jar" .pa/lib/
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "PA_SDK_VERSION=$version" >> "$GITHUB_ENV"
fi
echo "$version"
