# Use bash as shell
SHELL = /bin/bash

# Check for dirty :D 
define check_dirty
	GIT_SHA=$$(git rev-parse HEAD) || { \
		GIT_HASH=$${GIT_SHA:-NO_SHA}; \
	}; \
	if [ -z "$$GIT_HASH" ]; then \
		GIT_DIRTY=$$(git diff --stat); \
		if [ -n "$$GIT_DIRTY" ]; then \
			DIRTY="true"; \
		else \
			DIRTY="false"; \
		fi; \
	fi; \
	echo $$DIRTY
endef

# Authorino version
VERSION = $(shell git rev-parse HEAD)

# Authorino dirty
DIRTY = $(shell $(check_dirty))

# Use vi as default editor
EDITOR ?= vi

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
NAMESPACE ?= default

# Authorino instance name
AUTHORINO_INSTANCE ?= authorino

# TLS enabled/disabled
TLS_ENABLED ?= true

# Authorino CR
AUTHORINO_CR = $(PROJECT_DIR)/deploy/authorino.yaml

# Authorino Operator version
OPERATOR_VERSION ?= latest

.PHONY: help

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf " \033[36m%-30s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Dependencies

CONTROLLER_GEN = $(PROJECT_DIR)/bin/controller-gen
controller-gen: ## Installs controller-gen in $PROJECT_DIR/bin
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.9.0)

KUSTOMIZE = $(PROJECT_DIR)/bin/kustomize
kustomize: ## Installs kustomize in $PROJECT_DIR/bin
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v4@v4.5.5)

ENVTEST = $(PROJECT_DIR)/bin/setup-envtest
envtest: ## Installs setup-envtest in $PROJECT_DIR/bin
	$(call go-get-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.16)

MOCKGEN = $(PROJECT_DIR)/bin/mockgen
mockgen: ## Installs mockgen in $PROJECT_DIR/bin
	$(call go-get-tool,$(MOCKGEN),github.com/golang/mock/mockgen@v1.6.0)

BENCHSTAT = $(PROJECT_DIR)/bin/benchstat
benchstat: ## Installs benchstat in $PROJECT_DIR/bin
	$(call go-get-tool,$(BENCHSTAT),golang.org/x/perf/cmd/benchstat@latest)

KIND = $(PROJECT_DIR)/bin/kind
kind: ## Installs kind in $PROJECT_DIR/bin
	$(call go-get-tool,$(KIND),sigs.k8s.io/kind@v0.20.0)

ifeq ($(shell uname),Darwin)
SED=$(shell which gsed)
else
SED=$(shell which sed)
endif
sed: ## Checks if GNU sed is installed
ifeq ($(SED),)
	@echo "Cannot find GNU sed installed."
	exit 1
endif

# go-get-tool will 'go install' any package $2 and install it to $1.
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

##@ Development

.PHONY: vendor fmt vet generate manifests run build test benchmarks cover e2e docker-build

vendor: ## Downloads vendor dependencies
	go mod tidy
	go mod vendor

fmt: ## Runs go fmt against code
	go fmt ./...

vet: ## Runs go vet against code
	go vet ./...

generate: vendor controller-gen ## Generates types deepcopy code
	controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(MAKE) fmt vet

manifests: controller-gen kustomize ## Generates the manifests in $PROJECT_DIR/install
	controller-gen crd:crdVersions=v1 rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=install/crd output:rbac:artifacts:config=install/rbac && $(KUSTOMIZE) build install > $(AUTHORINO_MANIFESTS)
	$(MAKE) patch-webhook

run: generate manifests ## Runs the application against the Kubernetes cluster configured in ~/.kube/config
	go run -ldflags "-X main.version=$(VERSION)" ./main.go server

build: generate ## Builds the manager binary
	CGO_ENABLED=0 GO111MODULE=on go build -a -ldflags "-X main.version=$(VERSION) -X main.dirty=$(DIRTY)" -o bin/authorino main.go

IMAGE_REPO ?= authorino
using_semantic_version := $(shell [[ $(VERSION) =~ ^[0-9]+\.[0-9]+\.[0-9]+(-.+)?$$ ]] && echo "true")
ifdef using_semantic_version
IMAGE_TAG=v$(VERSION)
else
IMAGE_TAG=local
endif
AUTHORINO_IMAGE ?= $(IMAGE_REPO):$(IMAGE_TAG)
docker-build: ## Builds an image based on the current branch
	docker build --build-arg GIT_SHA=$(VERSION) --build-arg DIRTY=$(DIRTY) -t $(AUTHORINO_IMAGE) .

test: generate manifests envtest ## Runs the tests
	KUBEBUILDER_ASSETS='$(strip $(shell $(ENVTEST) use -p path 1.21.2 --os linux))' go test ./... -coverprofile cover.out

BENCHMARKS_FILE=benchmarks.out
benchmarks: generate manifests envtest benchstat ## Runs the test with benchmarks
	KUBEBUILDER_ASSETS='$(strip $(shell $(ENVTEST) use -p path 1.21.2 --os linux))' go test ./... -bench=. -run=^Benchmark -count=10 -cpu=1,4,10 -benchmem | tee $(BENCHMARKS_FILE)
	$(MAKE) report-benchmarks

report-benchmarks:
	$(BENCHSTAT) -filter "-.name:JSONPatternMatchingAuthz AND -.name:OPAAuthz" -table .name current=$(BENCHMARKS_FILE)
	$(BENCHSTAT) -filter ".name:/(JSONPatternMatchingAuthz|OPAAuthz)/" -col ".name@(OPAAuthz JSONPatternMatchingAuthz)" -table "" current=$(BENCHMARKS_FILE)

cover: ## Shows test coverage
	go tool cover -html=cover.out

AUTHCONFIG_VERSION ?= v1beta2
VERBOSE ?= 0
e2e: ## Runs the end-to-end tests on a local environment setup
	$(MAKE) local-setup NAMESPACE=authorino KIND_CLUSTER_NAME=authorino-e2e AUTHORINO_IMAGE=$(AUTHORINO_IMAGE) TLS_ENABLED=$(TLS_ENABLED) OPERATOR_BRANCH=$(OPERATOR_BRANCH) AUTHORINO_MANIFESTS=$(AUTHORINO_MANIFESTS) AUTHORINO_INSTANCE=$(AUTHORINO_INSTANCE) ENVOY_OVERLAY=$(ENVOY_OVERLAY) DEPLOY_KEYCLOAK=1 FF=1
	NAMESPACE=authorino AUTHCONFIG_VERSION=$(AUTHCONFIG_VERSION) VERBOSE=$(VERBOSE) ./tests/e2e-test.sh

##@ Apps

.PHONY: user-apps keycloak dex limitador

DEPLOY_KEYCLOAK ?= $(DEPLOY_IDPS)
DEPLOY_DEX ?= $(DEPLOY_IDPS)
ifeq (true,$(TLS_ENABLED))
ENVOY_OVERLAY = tls
else
ENVOY_OVERLAY = notls
endif
user-apps: ## Deploys the following user apps from kuadrant/authorino-examples into the Kubernetes cluster configured in ~/.kube/config: Talker API and Envoy proxy, and (optionally) Keycloak and Dex
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-$(ENVOY_OVERLAY)-deploy.yaml
ifneq (, $(DEPLOY_KEYCLOAK))
	$(MAKE) keycloak NAMESPACE=$(NAMESPACE)
endif
ifneq (, $(DEPLOY_DEX))
	$(MAKE) dex NAMESPACE=$(NAMESPACE)
endif

keycloak: ## Deploys Keycloak from kuadrant/authorino-examples into the Kubernetes cluster configured in ~/.kube/config
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml

dex: ## Deploys Dex from kuadrant/authorino-examples into the Kubernetes cluster configured in ~/.kube/config
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/dex/dex-deploy.yaml

limitador: ## Deploys Limitador from kuadrant/authorino-examples into the Kubernetes cluster configured in ~/.kube/config
	kubectl -n $(NAMESPACE) apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/limitador/limitador-deploy.yaml

##@ Installation

.PHONY: install-operator uninstall-operator install uninstall patch-webhook

AUTHORINO_OPERATOR_NAMESPACE ?= authorino-operator

ifeq (latest,$(OPERATOR_VERSION))
OPERATOR_BRANCH = main
else
OPERATOR_BRANCH = $(OPERATOR_VERSION)
endif
install-operator: ## Installs Authorino Operator and dependencies into the Kubernetes cluster configured in ~/.kube/config
	curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/$(OPERATOR_BRANCH)/utils/install.sh | bash -s -- --git-ref $(OPERATOR_BRANCH)
	kubectl patch deployment/authorino-webhooks -n $(AUTHORINO_OPERATOR_NAMESPACE) -p '{"spec":{"template":{"spec":{"containers":[{"name":"webhooks","image":"$(AUTHORINO_IMAGE)","imagePullPolicy":"IfNotPresent"}]}}}}'
	kubectl -n $(AUTHORINO_OPERATOR_NAMESPACE) wait --timeout=300s --for=condition=Available deployments --all

uninstall-operator: ## Uninstalls Authorino Operator and corresponding version of the manifests from the Kubernetes cluster configured in ~/.kube/config
	kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/$(OPERATOR_BRANCH)/config/deploy/manifests.yaml

install: manifests ## Installs the current manifests (CRD, RBAC) into the Kubernetes cluster configured in ~/.kube/config
	kubectl apply -f $(AUTHORINO_MANIFESTS)

uninstall: manifests ## Uninstalls the current manifests (CRD, RBAC) from the Kubernetes cluster configured in ~/.kube/config
	kubectl delete -f $(AUTHORINO_MANIFESTS)

patch-webhook: export WEBHOOK_NAMESPACE=$(AUTHORINO_OPERATOR_NAMESPACE)
patch-webhook:
	envsubst \
			< $(AUTHORINO_MANIFESTS) \
			> $(AUTHORINO_MANIFESTS).tmp && \
	mv $(AUTHORINO_MANIFESTS).tmp $(AUTHORINO_MANIFESTS)

##@ Deployment

.PHONY: namespace certs deploy

namespace: ## Creates a namespace where to deploy Authorino
	kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -

certs: sed ## Requests TLS certificates for the Authorino instance if TLS is enabled, cert-manager.io is installed, and the secret is not already present
ifeq (true,$(TLS_ENABLED))
ifeq (,$(shell kubectl -n $(NAMESPACE) get secret/authorino-oidc-server-cert 2>/dev/null))
	$(SED) "s/\$$(AUTHORINO_INSTANCE)/$(AUTHORINO_INSTANCE)/g;s/\$$(NAMESPACE)/$(NAMESPACE)/g" deploy/certs.yaml | kubectl -n $(NAMESPACE) apply -f -
else
	echo "tls cert secret found."
endif
else
	echo "tls disabled."
endif

deploy: certs sed ## Deploys an instance of Authorino into the Kubernetes cluster configured in ~/.kube/config
	@{ \
	set -e ;\
	TEMP_FILE=/tmp/authorino-deploy-$$(openssl rand -hex 4).yaml ;\
	cp $(AUTHORINO_CR) $$TEMP_FILE ;\
	$(SED) -i "s/\$$(AUTHORINO_INSTANCE)/$(AUTHORINO_INSTANCE)/g;s/\$$(TLS_ENABLED)/$(TLS_ENABLED)/g" $$TEMP_FILE ;\
	if [ "$(FF)" != "1" ]; then \
	$(EDITOR) $$TEMP_FILE ;\
	fi ;\
	kubectl -n $(NAMESPACE) apply -f $$TEMP_FILE ;\
	rm -rf $$TEMP_FILE ;\
	}

##@ Local cluster

.PHONY: cluster local-build local-setup local-rollout local-cleanup

KIND_CLUSTER_NAME ?= authorino
cluster: kind ## Starts a local Kubernetes cluster using Kind
	$(KIND) create cluster --name $(KIND_CLUSTER_NAME)

local-build: kind docker-build ## Builds an image based on the current branch and pushes it to the registry into the local Kubernetes cluster started with Kind
	$(KIND) load docker-image $(AUTHORINO_IMAGE) --name $(KIND_CLUSTER_NAME)

local-setup: cluster local-build install-operator install namespace deploy user-apps ## Sets up a test/dev local Kubernetes server using Kind, loaded up with a freshly built Authorino image and apps
	kubectl -n $(NAMESPACE) wait --timeout=300s --for=condition=Available deployments --all
	@{ \
	echo "Now you can export the envoy service by doing:"; \
	echo "kubectl port-forward --namespace $(NAMESPACE) deployment/envoy 8000:8000"; \
	echo "After that, you can curl -H \"Host: myhost.com\" localhost:8000"; \
	}

local-rollout: local-build ## Rebuilds and pushes the docker image to the local Kubernetes cluster started using Kind, and redeploys Authorino
	kubectl -n $(NAMESPACE) rollout restart deployment/authorino

local-cleanup: kind ## Deletes the local Kubernetes cluster started using Kind
	$(KIND) delete cluster --name $(KIND_CLUSTER_NAME)
