#!/bin/bash

set -euo pipefail

export AUTHORINO_NAMESPACE="authorino"
export KIND_CLUSTER_NAME="authorino-integration"

load_image_and_deploy() {
  if command -v jq &> /dev/null; then
    for img in $(kubectl apply -f $1 -o json | jq -r '.items[] | select(.kind == "Deployment") | .spec.template.spec.containers[].image'); do
      docker image inspect $img && kind load docker-image $img --name ${KIND_CLUSTER_NAME}
    done
  fi

  kubectl -n "${AUTHORINO_NAMESPACE}" apply -f $1
}

kind delete cluster
kind create cluster

if [ ! -n "${SKIP_BUILD:-}" ]; then
  echo "Building Authorino"
  docker build -t authorino:devel ./
fi
kind load docker-image authorino:devel --name ${KIND_CLUSTER_NAME}

echo "Creating namespace"
kubectl create namespace "${AUTHORINO_NAMESPACE}"

echo "Deploying Keycloak"
load_image_and_deploy examples/keycloak.yaml

echo "Deploying Envoy"
load_image_and_deploy examples/envoy.yaml

echo "Deploying echo-api app"
load_image_and_deploy examples/echo-api.yaml

echo "Deploying Authorino"
kustomize build config/default | kubectl -n "${AUTHORINO_NAMESPACE}" apply -f -
kubectl -n "${AUTHORINO_NAMESPACE}" patch deployment authorino-controller-manager -p '{"spec": {"template": {"spec":{"containers":[{"name": "manager","image":"authorino:devel", "imagePullPolicy":"IfNotPresent"}]}}}}'

echo "Wait for all deployments to be up"
kubectl -n "${AUTHORINO_NAMESPACE}" wait --timeout=300s --for=condition=Available deployments --all

echo
echo "Now you can export the envoy service by doing:"
echo "kubectl port-forward --namespace authorino deployment/envoy 8000:8000"
echo "after that, you can curl -H \"Host: myhost.com\" localhost:8000"
echo
