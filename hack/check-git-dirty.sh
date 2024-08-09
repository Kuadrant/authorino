#!/usr/bin/env bash

# Check if git is installed
if ! command -v git &>/dev/null
then
    echo "git not found..." >&2
    exit 1
fi

# Get the git diff output
if output=$(git diff --stat 2>/dev/null)
then
    # Check if the output contains 'build.yaml' and '1 file changed'
    if echo "$output" | grep -q " build.yaml | 2 +-" && echo "$output" | grep -q "1 file changed, 1 insertion(+), 1 deletion(-)"
    then
        if git diff build.yaml | grep -E -q '^\+ *version:' && ! git diff build.yaml | grep -E -q '^\+ *(?!version:)' 
        then
            echo "false"
        fi
    else
        echo "true"
    fi
else
    # Not a git repository or error with git diff
    exit 1
fi
