#!/bin/bash

set -euo pipefail

export AUTHORINO_NAMESPACE="authorino"

echo "Deploying Authorino"
kubectl -n ${AUTHORINO_NAMESPACE} rollout restart $(kubectl -n ${AUTHORINO_NAMESPACE} get deployments -l app=authorino -l control-plane=controller-manager -o name)
