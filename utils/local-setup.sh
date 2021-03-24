#!/bin/bash

set -euo pipefail

export AUTHORINO_NAMESPACE="authorino"
export KIND_CLUSTER_NAME="authorino-integration"
kind delete cluster
kind create cluster --config ./utils/kind-cluster.yaml

echo "Building Authorino"
docker build -t authorino:devel ./
kind load docker-image authorino:devel --name ${KIND_CLUSTER_NAME}

echo "Creating namespace"
kubectl create namespace "${AUTHORINO_NAMESPACE}"

echo "Deploying Keycloak"
kubectl -n "${AUTHORINO_NAMESPACE}" apply -f examples/keycloak.yaml

echo "Deploying Envoy"
kubectl -n "${AUTHORINO_NAMESPACE}" apply -f examples/envoy.yaml

echo "Deploying echo-api app"
kubectl -n "${AUTHORINO_NAMESPACE}" apply -f examples/echo-api.yaml

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
