#!/bin/bash

set -euo pipefail

export AUTHORINO_NAMESPACE="authorino"

echo "Creating namespace"
kubectl create namespace "${AUTHORINO_NAMESPACE}"

echo "Deploying Envoy"
kubectl -n "${AUTHORINO_NAMESPACE}" apply -f examples/envoy/envoy-deploy.yaml

echo "Deploying Talker API"
kubectl -n "${AUTHORINO_NAMESPACE}" apply -f examples/talker-api/talker-api-deploy.yaml

if [ -n "${DEPLOY_IDPS:-}" ] || [ -n "${DEPLOY_KEYCLOAK:-}" ]; then
  echo "Deploying Keycloak"
  kubectl -n "${AUTHORINO_NAMESPACE}" apply -f examples/keycloak/keycloak-deploy.yaml
fi

if [ -n "${DEPLOY_IDPS:-}" ] || [ -n "${DEPLOY_DEX:-}" ]; then
  echo "Deploying dex"
  kubectl -n "${AUTHORINO_NAMESPACE}" apply -f examples/dex/dex-deploy.yaml
fi

echo "Deploying Authorino"
kustomize build config/default | kubectl -n "${AUTHORINO_NAMESPACE}" apply -f -
kubectl -n "${AUTHORINO_NAMESPACE}" patch deployment authorino-controller-manager -p '{"spec": {"template": {"spec":{"containers":[{"name": "manager", "imagePullPolicy":"IfNotPresent"}]}}}}'

echo "Wait for all deployments to be up"
kubectl -n "${AUTHORINO_NAMESPACE}" wait --timeout=300s --for=condition=Available deployments --all

echo
echo "Now you can export the envoy service by doing:"
echo "kubectl port-forward --namespace authorino deployment/envoy 8000:8000"
echo "after that, you can curl -H \"Host: myhost.com\" localhost:8000"
echo
