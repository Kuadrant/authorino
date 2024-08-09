#!/usr/bin/env bash

# Get the current git branch
branch=$(git rev-parse --abbrev-ref HEAD)

# Check if the branch is "main"
if [[ "$branch" == "main" ]]; then
    version="latest"
# Otherwise, use the branch name as the version
else
    version="$branch"
fi

# Use yq to set build.version to version variable
yq eval ".build.version = \"$version\"" -i build.yaml
