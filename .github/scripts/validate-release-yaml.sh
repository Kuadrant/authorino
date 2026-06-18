#!/usr/bin/env bash
set -euo pipefail

BRANCH="${1:?Branch name required}"
ORG="${2:-Kuadrant}"
RELEASE_YAML="${3:-release.yaml}"

if [[ ! -f "$RELEASE_YAML" ]]; then
  echo "::error::File not found: $RELEASE_YAML"
  exit 1
fi

VERSION=$(yq '.authorino.version' "$RELEASE_YAML")

if [[ "$BRANCH" != "main" && "$VERSION" == "0.0.0" ]]; then
  echo "::error::release.yaml version is 0.0.0 on branch '$BRANCH' -- must specify a release version on non-main branches"
  exit 1
fi

DEPS=$(yq '.dependencies | keys | .[]' "$RELEASE_YAML" 2>/dev/null || true)
for dep in $DEPS; do
  dep_version=$(yq ".dependencies.${dep}" "$RELEASE_YAML")
  if [[ "$dep_version" != "0.0.0" && "$dep_version" != "null" && -n "$dep_version" ]]; then
    if ! gh release view "v${dep_version}" --repo "${ORG}/${dep}" &>/dev/null; then
      echo "::error::Dependency '${dep}' targets version '${dep_version}', but release v${dep_version} does not exist in ${ORG}/${dep}"
      exit 1
    fi
  fi
done

echo "release.yaml validation passed"
