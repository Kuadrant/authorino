#!/usr/bin/env bash

if ! command -v git &>/dev/null
then
    echo "git not found..." >&2
    exit 1
fi

if output=$(git diff --stat 2>/dev/null)
then
[ -n "$output" ] && echo "true" || echo "false"
else
    # Not a git repository
    exit 1
fi
