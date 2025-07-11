# Use bash as shell
SHELL = /bin/bash

# Use vi as default editor
EDITOR ?= vi

# Container Engine to be used for building image and with kind
CONTAINER_ENGINE ?= docker
ifeq (podman,$(CONTAINER_ENGINE))
	CONTAINER_ENGINE_EXTRA_FLAGS ?= --load
endif

# Set version and image tag
ifeq ($(VERSION),)
VERSION = $(shell git rev-parse --abbrev-ref HEAD)
endif
ifeq ($(VERSION),main)
override VERSION = latest
endif
using_semantic_version := $(shell [[ $(VERSION) =~ ^[0-9]+\.[0-9]+\.[0-9]+(-.+)?$$ ]] && echo "true")
ifdef using_semantic_version
IMAGE_TAG=v$(VERSION)
else
IMAGE_TAG=dev
endif
IMAGE_REPO ?= localhost/authorino
AUTHORINO_IMAGE ?= $(IMAGE_REPO):$(IMAGE_TAG)

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

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KIND ?= $(LOCALBIN)/kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
MOCKGEN ?= $(LOCALBIN)/mockgen
BENCHSTAT ?= $(LOCALBIN)/benchstat
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KIND_VERSION ?= v0.20.0
KUSTOMIZE_VERSION ?= v5.5.0
CONTROLLER_GEN_VERSION ?= v0.15.0
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
MOCKGEN_VERSION ?= v0.5.2
BENCHSTAT_VERSION ?= latest
GOLANGCI_LINT_VERSION ?= v2.1.6

## Versioned Binaries (the actual files that 'make' will check for)
KIND_V_BINARY := $(LOCALBIN)/kind-$(KIND_VERSION)
KUSTOMIZE_V_BINARY := $(LOCALBIN)/kustomize-$(KUSTOMIZE_VERSION)
CONTROLLER_GEN_V_BINARY := $(LOCALBIN)/controller-gen-$(CONTROLLER_GEN_VERSION)
ENVTEST_V_BINARY := $(LOCALBIN)/setup-envtest-$(ENVTEST_VERSION)
MOCKGEN_V_BINARY := $(LOCALBIN)/mockgen-$(MOCKGEN_VERSION)
BENCHSTAT_V_BINARY := $(LOCALBIN)/benchstat-$(BENCHSTAT_VERSION)
GOLANGCI_LINT_V_BINARY = $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)

.PHONY: kustomize
kustomize: $(KUSTOMIZE_V_BINARY) ## Download kustomize locally if necessary.
$(KUSTOMIZE_V_BINARY): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN_V_BINARY) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN_V_BINARY): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_GEN_VERSION))

.PHONY: envtest
envtest: $(ENVTEST_V_BINARY) ## Download setup-envtest locally if necessary.
$(ENVTEST_V_BINARY): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: mockgen
mockgen: $(MOCKGEN_V_BINARY)
$(MOCKGEN_V_BINARY): $(LOCALBIN) ## Installs mockgen in $PROJECT_DIR/bin
	$(call go-install-tool,$(MOCKGEN),go.uber.org/mock/mockgen,$(MOCKGEN_VERSION))

.PHONY: benchstat
benchstat: $(BENCHSTAT_V_BINARY)
$(BENCHSTAT_V_BINARY): $(LOCALBIN) ## Installs benchstat in $PROJECT_DIR/bin
	$(call go-install-tool,$(BENCHSTAT),golang.org/x/perf/cmd/benchstat,$(BENCHSTAT_VERSION))

.PHONY: kind
kind: $(KIND_V_BINARY)
$(KIND_V_BINARY): $(LOCALBIN)  ## Installs kind in $PROJECT_DIR/bin
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

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

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
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
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(MAKE) fmt vet

manifests: controller-gen kustomize ## Generates the manifests in $PROJECT_DIR/install
	$(CONTROLLER_GEN) crd:crdVersions=v1 rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=install/crd output:rbac:artifacts:config=install/rbac && $(KUSTOMIZE) build install > $(AUTHORINO_MANIFESTS)
	$(MAKE) patch-webhook

run:git_sha=$(shell git rev-parse HEAD)
run:dirty=$(shell $(PROJECT_DIR)/hack/check-git-dirty.sh || echo "unknown")
run: generate manifests ## Runs the application against the Kubernetes cluster configured in ~/.kube/config
	go run -ldflags "-X main.version=$(VERSION) -X main.gitSHA=${git_sha} -X main.dirty=${dirty}" ./main.go server

build:git_sha=$(shell git rev-parse HEAD)
build:dirty=$(shell $(PROJECT_DIR)/hack/check-git-dirty.sh || echo "unknown")
build: generate ## Builds the manager binary
	CGO_ENABLED=0 GO111MODULE=on go build -a -ldflags "-X main.version=$(VERSION) -X main.gitSHA=${git_sha} -X main.dirty=${dirty}" -o bin/authorino main.go

docker-build:git_sha=$(shell git rev-parse HEAD)
docker-build:dirty=$(shell $(PROJECT_DIR)/hack/check-git-dirty.sh || echo "unknown")
docker-build: ## Builds an image based on the current branch
	$(CONTAINER_ENGINE) build \
	  --build-arg version=$(VERSION) \
		--build-arg git_sha=$(git_sha) \
		--build-arg dirty=$(dirty) \
		$(CONTAINER_ENGINE_EXTRA_FLAGS) \
		-t $(AUTHORINO_IMAGE) .

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

AUTHCONFIG_VERSION ?= v1beta3
VERBOSE ?= 0
e2e: ## Runs the end-to-end tests on a local environment setup
	$(MAKE) local-setup NAMESPACE=authorino KIND_CLUSTER_NAME=authorino-e2e AUTHORINO_IMAGE=$(AUTHORINO_IMAGE) TLS_ENABLED=$(TLS_ENABLED) OPERATOR_BRANCH=$(OPERATOR_BRANCH) AUTHORINO_MANIFESTS=$(AUTHORINO_MANIFESTS) AUTHORINO_INSTANCE=$(AUTHORINO_INSTANCE) ENVOY_OVERLAY=$(ENVOY_OVERLAY) DEPLOY_KEYCLOAK=1 FF=1
	NAMESPACE=authorino AUTHCONFIG_VERSION=$(AUTHCONFIG_VERSION) VERBOSE=$(VERBOSE) ./tests/e2e-test.sh

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

##@ Apps

.PHONY: user-apps keycloak dex limitador cert-manager

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

cert-manager:
ifeq (true,$(TLS_ENABLED))
	kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.1/cert-manager.yaml
	kubectl -n cert-manager wait --timeout=300s --for=condition=Available deployments --all
endif

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
#	kubectl patch deployment/authorino-webhooks -n $(AUTHORINO_OPERATOR_NAMESPACE) -p '{"spec":{"template":{"spec":{"containers":[{"name":"webhooks","image":"$(AUTHORINO_IMAGE)","imagePullPolicy":"IfNotPresent"}]}}}}'
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
	$(eval TMP_DIR := $(shell mktemp -d))
	$(CONTAINER_ENGINE) save -o $(TMP_DIR)/image.tar $(AUTHORINO_IMAGE) \
		&& KIND_EXPERIMENTAL_PROVIDER=$(CONTAINER_ENGINE) $(KIND) load image-archive $(TMP_DIR)/image.tar --name $(KIND_CLUSTER_NAME) ; \
		EXITVAL=$$? ; \
		rm -rf $(TMP_DIR) ;\
		exit $${EXITVAL}

local-setup: cluster cert-manager local-build install-operator install namespace deploy user-apps ## Sets up a test/dev local Kubernetes server using Kind, loaded up with a freshly built Authorino image and apps
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
