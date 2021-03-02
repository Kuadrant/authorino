#!/bin/bash

set -euo pipefail

export AUTHORINO_NAMESPACE="authorino"
export KIND_CLUSTER_NAME="authorino-integration"

echo "Building Authorino"
docker build -t authorino:devel ./
kind load docker-image authorino:devel --name ${KIND_CLUSTER_NAME}

echo "Deploying Authorino"
kubectl -n ${AUTHORINO_NAMESPACE} rollout restart $(kubectl -n ${AUTHORINO_NAMESPACE} get deployments -l app=authorino -l control-plane=controller-manager -o name)
