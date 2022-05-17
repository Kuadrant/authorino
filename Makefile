# Use bash as shell
SHELL = /bin/bash

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
export PATH := $(PROJECT_DIR)/bin:$(PATH)

# Authorino manifests bundle (CRDs, RBAC)
AUTHORINO_MANIFESTS ?= $(PROJECT_DIR)/install/manifests.yaml

# The Kubernetes namespace where to deploy the Authorino instance
NAMESPACE ?= authorino

# Authorino instance name
AUTHORINO_INSTANCE ?= authorino

# TLS enabled/disabled
TLS_ENABLED ?= true

# Authorino CR
AUTHORINO_CR = $(PROJECT_DIR)/deploy/authorino.yaml

# Authorino Operator version
OPERATOR_VERSION ?= latest

.PHONY: vendor fmt vet generate manager manifests run test cover install  uninstall install-operator deploy cert-manager certs

# Download vendor dependencies
vendor:
	go mod tidy
	go mod vendor

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

bin/controller-gen:
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	GOBIN=$(PROJECT_DIR)/bin go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.6.1 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}

controller-gen: bin/controller-gen

# Generate code
generate: vendor controller-gen
	controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(MAKE) fmt vet

# Build manager binary
manager: generate
	go build -o bin/authorino main.go

bin/kustomize:
	@{ \
	set -e ;\
	KUSTOMIZE_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$KUSTOMIZE_GEN_TMP_DIR ;\
	go mod init tmp ;\
	GOBIN=$(PROJECT_DIR)/bin go get sigs.k8s.io/kustomize/kustomize/v3@v3.5.4 ;\
	rm -rf $$KUSTOMIZE_GEN_TMP_DIR ;\
	}

kustomize: bin/kustomize

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	controller-gen crd:trivialVersions=true,crdVersions=v1 rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=install/crd output:rbac:artifacts:config=install/rbac && kustomize build install > $(AUTHORINO_MANIFESTS)

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate manifests
	go run ./main.go

setup-envtest:
ifeq (, $(shell which setup-envtest))
	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
SETUP_ENVTEST=$(GOBIN)/setup-envtest
else
SETUP_ENVTEST=$(shell which setup-envtest)
endif

# Run the tests
test: generate manifests setup-envtest
	KUBEBUILDER_ASSETS='$(strip $(shell $(SETUP_ENVTEST) use -p path 1.21.2))'  go test ./... -coverprofile cover.out

# Show test coverage
cover:
	go tool cover -html=cover.out

# Install CRDs into a cluster
install: manifests
	kubectl apply -f $(AUTHORINO_MANIFESTS)

# Uninstall CRDs from a cluster
uninstall: manifests
	kubectl delete -f $(AUTHORINO_MANIFESTS)

ifeq (latest,$(OPERATOR_VERSION))
OPERATOR_BRANCH = main
else
OPERATOR_BRANCH = $(OPERATOR_VERSION)
endif
install-operator:
	kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/$(OPERATOR_BRANCH)/config/deploy/manifests.yaml
	kubectl -n authorino-operator wait --timeout=300s --for=condition=Available deployments --all

# Creates a namespace where to deploy Authorino
namespace:
	kubectl create namespace $(NAMESPACE)

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: certs
	@{ \
	set -e ;\
	TEMP_FILE=/tmp/authorino-deploy-$$(openssl rand -hex 4).yaml ;\
	cp $(AUTHORINO_CR) $$TEMP_FILE ;\
	sed -i "s/\$$(AUTHORINO_INSTANCE)/$(AUTHORINO_INSTANCE)/g;s/\$$(TLS_ENABLED)/$(TLS_ENABLED)/g" $$TEMP_FILE ;\
	if [ "$(FF)" != "1" ]; then \
	$(EDITOR) $$TEMP_FILE ;\
	fi ;\
	kubectl -n $(NAMESPACE) apply -f $$TEMP_FILE ;\
	rm -rf $$TEMP_FILE ;\
	}

# Install CertManager to the Kubernetes cluster
cert-manager:
ifeq (true,$(TLS_ENABLED))
	kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
	kubectl delete mutatingwebhookconfiguration.admissionregistration.k8s.io/cert-manager-webhook
	kubectl delete validatingwebhookconfigurations.admissionregistration.k8s.io/cert-manager-webhook
	kubectl -n cert-manager wait --timeout=300s --for=condition=Available deployments --all
endif

# Requests TLS certificates for services if cert-manager.io is installed, the secret is not already present and TLS is enabled
certs:
ifeq (true,$(TLS_ENABLED))
ifeq (,$(shell kubectl -n $(NAMESPACE) get secret/authorino-oidc-server-cert 2>/dev/null))
	sed "s/\$$(AUTHORINO_INSTANCE)/$(AUTHORINO_INSTANCE)/g;s/\$$(NAMESPACE)/$(NAMESPACE)/g" deploy/certs.yaml | kubectl -n $(NAMESPACE) apply -f -
else
	echo "tls cert secret found."
endif
else
	echo "tls disabled."
endif

# Local setup...........................................................................................................

.PHONY: namespace example-apps limitador cluster local-build local-setup local-rollout local-cleanup e2e

KIND_VERSION=v0.11.1
kind:
ifneq ($(KIND_VERSION), $(shell kind version | cut -d' ' -f2))
	go install sigs.k8s.io/kind@$(KIND_VERSION)
KIND=$(GOBIN)/kind
else
KIND=$(shell which kind)
endif

# Start a local Kubernetes cluster using Kind
KIND_CLUSTER_NAME ?= authorino
cluster: kind
	kind create cluster --name $(KIND_CLUSTER_NAME)

# Builds an image based on the current branch and pushes it to the registry of the local Kubernetes cluster started with Kind
AUTHORINO_IMAGE ?= authorino:local
local-build: kind
	docker build -t $(AUTHORINO_IMAGE) .
	kind load docker-image $(AUTHORINO_IMAGE) --name $(KIND_CLUSTER_NAME)

# Set up a test/dev local Kubernetes server loaded up with a freshly built Authorino image plus dependencies
local-setup: cluster local-build cert-manager install-operator install namespace deploy example-apps
	kubectl -n $(NAMESPACE) wait --timeout=300s --for=condition=Available deployments --all
	@{ \
	echo "Now you can export the envoy service by doing:"; \
	echo "kubectl port-forward --namespace $(NAMESPACE) deployment/envoy 8000:8000"; \
	echo "After that, you can curl -H \"Host: myhost.com\" localhost:8000"; \
	}

# Rebuild and push the docker image and redeploy Authorino to the local k8s cluster
local-rollout: local-build
	kubectl -n $(NAMESPACE) rollout restart deployment/authorino

# Deletes the local Kubernetes cluster started using Kind
local-cleanup: kind
	kind delete cluster --name $(KIND_CLUSTER_NAME)

# Deploys the examples user apps: Talker API and Envoy proxy, and optionally Keycloak and Dex
DEPLOY_KEYCLOAK ?= $(DEPLOY_IDPS)
DEPLOY_DEX ?= $(DEPLOY_IDPS)
ifeq (true,$(TLS_ENABLED))
ENVOY_OVERLAY = tls
else
ENVOY_OVERLAY = notls
endif
example-apps:
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-$(ENVOY_OVERLAY)-deploy.yaml
ifneq (, $(DEPLOY_KEYCLOAK))
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
endif
ifneq (, $(DEPLOY_DEX))
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/dex/dex-deploy.yaml
endif

# Install Limitador to the Kubernetes cluster
limitador:
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/limitador/limitador-deploy.yaml

VERBOSE ?= 0
e2e:
	$(MAKE) local-setup NAMESPACE=$(NAMESPACE) KIND_CLUSTER_NAME=authorino-e2e AUTHORINO_IMAGE=$(AUTHORINO_IMAGE) TLS_ENABLED=$(TLS_ENABLED) OPERATOR_BRANCH=$(OPERATOR_BRANCH) AUTHORINO_MANIFESTS=$(AUTHORINO_MANIFESTS) AUTHORINO_INSTANCE=$(AUTHORINO_INSTANCE) ENVOY_OVERLAY=$(ENVOY_OVERLAY) DEPLOY_KEYCLOAK=1 FF=1
	NAMESPACE=$(NAMESPACE) VERBOSE=$(VERBOSE) ./tests/e2e-test.sh
