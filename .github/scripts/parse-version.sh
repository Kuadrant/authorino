#!/usr/bin/env bash
set -euo pipefail

RELEASE_YAML="${1:-release.yaml}"

if [[ ! -f "$RELEASE_YAML" ]]; then
  echo "::error::File not found: $RELEASE_YAML"
  exit 1
fi

VERSION=$(yq '.authorino.version' "$RELEASE_YAML")
if [[ -z "$VERSION" || "$VERSION" == "null" ]]; then
  echo "::error::No version found in $RELEASE_YAML under authorino.version"
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "::error::Invalid semver: $VERSION"
  exit 1
fi

MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)
PATCH=$(echo "$VERSION" | cut -d. -f3 | cut -d- -f1)
RELEASE_BRANCH="release-${MAJOR}.${MINOR}"

echo "version=$VERSION" >> "${GITHUB_OUTPUT:-/dev/stdout}"
echo "major=$MAJOR" >> "${GITHUB_OUTPUT:-/dev/stdout}"
echo "minor=$MINOR" >> "${GITHUB_OUTPUT:-/dev/stdout}"
echo "patch=$PATCH" >> "${GITHUB_OUTPUT:-/dev/stdout}"
echo "release-branch=$RELEASE_BRANCH" >> "${GITHUB_OUTPUT:-/dev/stdout}"
