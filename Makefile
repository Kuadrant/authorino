#Use bash as shell
SHELL = /bin/bash

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))

# Image URL to use all building/pushing image targets
DEFAULT_AUTHORINO_IMAGE = quay.io/3scale/authorino:latest
AUTHORINO_IMAGE ?= $(DEFAULT_AUTHORINO_IMAGE)
# The Kubernetes namespace where to deploy the Authorino instance.
AUTHORINO_NAMESPACE ?= authorino
# Flavour of the Authorino deployment – Options: 'namespaced' (default), 'cluster-wide'
AUTHORINO_DEPLOYMENT ?= namespaced
# Number of Authorino replicas
AUTHORINO_REPLICAS ?= 1

all: manager


test: generate fmt vet manifests setup-envtest
	KUBEBUILDER_ASSETS='$(strip $(shell $(SETUP_ENVTEST) use -p path 1.21.2))'  go test ./... -coverprofile cover.out

# Show test coverage
cover:
	go tool cover -html=cover.out

# Build manager binary
manager: generate fmt vet
	go build -o bin/authorino main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go

# Install CRDs into a cluster
install: manifests $(KUSTOMIZE)
	$(KUSTOMIZE) build install | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests $(KUSTOMIZE)
	$(KUSTOMIZE) build install | kubectl delete -f -

# Requests TLS certificates for services if cert-manager.io is installed, the secret is not already present and TLS is enabled
.PHONY: certs
TLS_CERT_SECRET_CHECK = $(shell kubectl -n $(AUTHORINO_NAMESPACE) get secret/authorino-oidc-server-cert 2>/dev/null)
CERT_MANAGER_CHECK = $(shell kubectl get crds/issuers.cert-manager.io 2>/dev/null)
certs:
ifeq (,$(findstring -notls,$(AUTHORINO_DEPLOYMENT)))
ifeq (,$(TLS_CERT_SECRET_CHECK))
ifneq (, $(CERT_MANAGER_CHECK))
	cd deploy/base/certmanager && $(KUSTOMIZE) edit set namespace $(AUTHORINO_NAMESPACE)
	$(KUSTOMIZE) build deploy/base/certmanager | kubectl -n $(AUTHORINO_NAMESPACE) apply -f -
	cd deploy/base/certmanager && $(KUSTOMIZE) edit set namespace authorino
else
	echo "cert-manager not installed."
endif
else
	echo "tls cert secret found."
endif
else
	echo "tls disabled."
endif

CONTROLLER_GEN=$(PROJECT_DIR)/bin/controller-gen
# find or download controller-gen
# download controller-gen if necessary
$(CONTROLLER_GEN):
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	GOBIN=$(PROJECT_DIR)/bin go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.6.1 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}

controller-gen: $(CONTROLLER_GEN)

KUSTOMIZE = $(PROJECT_DIR)/bin/kustomize
# Download kustomize locally if necessary
$(KUSTOMIZE):
	@{ \
	set -e ;\
	KUSTOMIZE_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$KUSTOMIZE_GEN_TMP_DIR ;\
	go mod init tmp ;\
	GOBIN=$(PROJECT_DIR)/bin go get sigs.k8s.io/kustomize/kustomize/v3@v3.5.4 ;\
	rm -rf $$KUSTOMIZE_GEN_TMP_DIR ;\
	}

kustomize: $(KUSTOMIZE)

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests $(KUSTOMIZE)
	$(MAKE) certs AUTHORINO_NAMESPACE=$(AUTHORINO_NAMESPACE) AUTHORINO_DEPLOYMENT=$(AUTHORINO_DEPLOYMENT)
	cd deploy/base && $(KUSTOMIZE) edit set image authorino=$(AUTHORINO_IMAGE) && $(KUSTOMIZE) edit set namespace $(AUTHORINO_NAMESPACE) && $(KUSTOMIZE) edit set replicas authorino-controller-manager=$(AUTHORINO_REPLICAS)
	cd deploy/overlays/$(AUTHORINO_DEPLOYMENT) && $(KUSTOMIZE) edit set namespace $(AUTHORINO_NAMESPACE)
	$(KUSTOMIZE) build deploy/overlays/$(AUTHORINO_DEPLOYMENT) | kubectl -n $(AUTHORINO_NAMESPACE) apply -f -
# rollback kustomize edit
	cd deploy/base && $(KUSTOMIZE) edit set image authorino=$(DEFAULT_AUTHORINO_IMAGE) && $(KUSTOMIZE) edit set namespace authorino && $(KUSTOMIZE) edit set replicas authorino-controller-manager=1
	cd deploy/overlays/$(AUTHORINO_DEPLOYMENT) && $(KUSTOMIZE) edit set namespace authorino

# Generate manifests e.g. CRD, RBAC etc.
manifests: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) crd:trivialVersions=true,crdVersions=v1 rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=install/crd  output:rbac:artifacts:config=install/rbac

# Download vendor dependencies
.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: vendor $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build: vendor
	docker build . -t ${AUTHORINO_IMAGE}

# Push the docker image
docker-push:
	docker push ${AUTHORINO_IMAGE}


KIND_VERSION=v0.11.1

kind:
ifneq ($(KIND_VERSION), $(shell kind version | cut -d' ' -f2))
	go install sigs.k8s.io/kind@$(KIND_VERSION)
KIND=$(GOBIN)/kind
else
KIND=$(shell which kind)
endif

setup-envtest:
ifeq (, $(shell which setup-envtest))
	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
SETUP_ENVTEST=$(GOBIN)/setup-envtest
else
SETUP_ENVTEST=$(shell which setup-envtest)
endif


# Prints relevant environment variables
.PHONY: envs
envs:
	@{ \
	echo "CONTROLLER_GEN=$(CONTROLLER_GEN)"; \
	echo "KUSTOMIZE=$(KUSTOMIZE)"; \
	echo "AUTHORINO_IMAGE=$(AUTHORINO_IMAGE)"; \
	echo "AUTHORINO_NAMESPACE=$(AUTHORINO_NAMESPACE)"; \
	echo "AUTHORINO_DEPLOYMENT=$(AUTHORINO_DEPLOYMENT)"; \
	echo "AUTHORINO_REPLICAS=$(AUTHORINO_REPLICAS)"; \
	}

# Creates a namespace where to deploy Authorino
.PHONY: namespace
namespace:
	kubectl create namespace $(AUTHORINO_NAMESPACE)

# Deploys the examples user apps: Talker API and Envoy proxy, and optionally Keycloak and Dex
.PHONY: example-apps
NAMESPACE ?= $(AUTHORINO_NAMESPACE)
DEPLOY_KEYCLOAK ?= $(DEPLOY_IDPS)
DEPLOY_DEX ?= $(DEPLOY_IDPS)
ifeq (,$(findstring -notls,$(AUTHORINO_DEPLOYMENT)))
ENVOY_OVERLAY = tls
else
ENVOY_OVERLAY = notls
endif
example-apps:
	kubectl -n $(NAMESPACE) apply -f examples/talker-api/talker-api-deploy.yaml
	$(KUSTOMIZE) build examples/envoy/overlays/$(ENVOY_OVERLAY) | kubectl -n $(NAMESPACE) apply -f -
ifneq (, $(DEPLOY_KEYCLOAK))
	kubectl -n $(NAMESPACE) apply -f examples/keycloak/keycloak-deploy.yaml
endif
ifneq (, $(DEPLOY_DEX))
	kubectl -n $(NAMESPACE) apply -f examples/dex/dex-deploy.yaml
endif

# Install CertManager to the Kubernetes cluster
.PHONY: cert-manager
cert-manager:
ifeq (,$(findstring -notls,$(AUTHORINO_DEPLOYMENT)))
	kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
	kubectl delete mutatingwebhookconfiguration.admissionregistration.k8s.io/cert-manager-webhook
	kubectl delete validatingwebhookconfigurations.admissionregistration.k8s.io/cert-manager-webhook
	kubectl -n cert-manager wait --timeout=300s --for=condition=Available deployments --all
endif

# Install Limitador to the Kubernetes cluster
.PHONY: limitador
NAMESPACE ?= $(AUTHORINO_NAMESPACE)
limitador:
	kubectl -n $(NAMESPACE) apply -f examples/limitador/limitador-deploy.yaml

# Targets with the 'local-' prefix, for trying Authorino in a local cluster spawned with Kind

KIND_CLUSTER_NAME ?= authorino

# Start a local Kubernetes cluster using Kind
.PHONY: local-cluster-up
local-cluster-up: kind
	kind create cluster --name $(KIND_CLUSTER_NAME)

# Builds an image locally and pushes it to the registry of the Kind-started local Kubernetes cluster
.PHONY: local-build-and-push
local-build-and-push:
ifneq (1, $(SKIP_LOCAL_BUILD))
	$(eval AUTHORINO_IMAGE = authorino:local)
	$(MAKE) docker-build AUTHORINO_IMAGE=$(AUTHORINO_IMAGE)
	$(MAKE) local-push AUTHORINO_IMAGE=$(AUTHORINO_IMAGE)
endif

# Pushes the Authorino image to the registry of the Kind-started local Kubernetes cluster
.PHONY: local-push
local-push: kind
	kind load docker-image $(AUTHORINO_IMAGE) --name $(KIND_CLUSTER_NAME)

# Deploys Authorino and sets imagePullPolicy to 'IfNotPresent' (so it doesn't try to pull the image which may have just been pushed into the server registry)
.PHONY: local-deploy
local-deploy: deploy
	kubectl -n $(AUTHORINO_NAMESPACE) patch deployment authorino-controller-manager -p '{"spec": {"template": {"spec":{"containers":[{"name": "manager", "imagePullPolicy":"IfNotPresent"}]}}}}'

# Set up a test/dev local Kubernetes server loaded up with a freshly built Authorino image plus dependencies
.PHONY: local-setup
local-setup: local-cluster-up local-build-and-push cert-manager install namespace local-deploy example-apps
	kubectl -n $(AUTHORINO_NAMESPACE) wait --timeout=300s --for=condition=Available deployments --all
	@{ \
	echo "Now you can export the envoy service by doing:"; \
	echo "kubectl port-forward --namespace $(NAMESPACE) deployment/envoy 8000:8000"; \
	echo "After that, you can curl -H \"Host: myhost.com\" localhost:8000"; \
	}

# Rebuild and push the docker image and redeploy Authorino to the local k8s cluster
.PHONY: local-rollout
local-rollout: local-build-and-push
	kubectl -n $(AUTHORINO_NAMESPACE) rollout restart deployment.apps/authorino-controller-manager

# Deletes the local Kubernetes cluster started using Kind
.PHONY: local-cleanup
local-cleanup: kind
	kind delete cluster --name $(KIND_CLUSTER_NAME)
