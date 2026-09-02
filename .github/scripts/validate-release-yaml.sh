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

ERRORS=0
ENTRIES=$(yq -o=json '.dependencies // {} | to_entries[]' "$RELEASE_YAML" 2>/dev/null || true)
if [[ -n "$ENTRIES" ]]; then
  while IFS= read -r entry; do
    dep=$(echo "$entry" | jq -r '.key')
    dep_version=$(echo "$entry" | jq -r '.value')
    if [[ "$dep_version" != "0.0.0" && "$dep_version" != "null" && -n "$dep_version" ]]; then
      draft_status=$(gh release view "v${dep_version}" --repo "${ORG}/${dep}" --json isDraft -q '.isDraft' 2>/dev/null) || {
        echo "::error::Dependency '${dep}' targets version '${dep_version}', but release v${dep_version} does not exist in ${ORG}/${dep}"
        ERRORS=$((ERRORS + 1))
        continue
      }
      if [[ "$draft_status" == "true" ]]; then
        echo "::error::Dependency '${dep}' targets version '${dep_version}', but release v${dep_version} in ${ORG}/${dep} is a draft"
        ERRORS=$((ERRORS + 1))
      fi
    fi
  done < <(echo "$ENTRIES" | jq -c '.')
fi

if [[ "$ERRORS" -gt 0 ]]; then
  echo "::error::release.yaml validation failed with ${ERRORS} dependency error(s)"
  exit 1
fi

echo "release.yaml validation passed"
