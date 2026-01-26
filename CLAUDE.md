# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Authorino is a Kubernetes-native authorization service that implements Envoy's external authorization gRPC protocol. It acts as an authorization layer between Envoy proxy and upstream services, providing hybrid API security with support for multiple authentication protocols (JWT/OIDC, API keys, mTLS, OAuth2 token introspection, Kubernetes TokenReview) and authorization mechanisms (pattern-matching, OPA/Rego, Kubernetes SubjectAccessReview, SpiceDB).

## Essential Commands

### Development Workflow

```bash
# Download dependencies
make vendor

# Run tests
make test

# Run benchmarks
make benchmarks

# Build the binary
make build

# Build Docker image
make docker-build

# Run linter
make lint

# Fix linting issues
make lint-fix
```

### Code Generation

```bash
# Generate deepcopy code for types
make generate

# Generate CRDs and RBAC manifests
make manifests
```

### Local Development with Kind

```bash
# Full local setup (cluster + deps + build + deploy + apps)
make local-setup

# Rebuild and redeploy after code changes
make local-rollout

# Delete local cluster
make local-cleanup

# Port forward to Envoy for testing
kubectl port-forward deployment/envoy 8000:8000
```

### Running Single Tests

```bash
# Run specific test
go test ./pkg/auth -run TestSpecificFunction

# Run with verbose output
go test -v ./pkg/evaluators/...

# Run with race detection
go test -race ./...
```

## Architecture

### Core Components

**Auth Pipeline**: Authorino processes requests through a 5-phase pipeline:
1. **Authentication** (phase i): Verify identity from credentials (at least one must succeed)
2. **Metadata** (phase ii): Fetch external data to enrich context
3. **Authorization** (phase iii): Evaluate policies (all must pass)
4. **Response** (phase iv): Build dynamic responses (headers, wristbands, dynamic metadata)
5. **Callbacks** (phase v): Send HTTP callbacks

**Index**: In-memory data structure that maps hosts to AuthConfig specs. Built and reconciled by watching AuthConfig and Secret resources.

**Authorization JSON**: Working memory for each request containing `context` (request data from Envoy) and `auth` (resolved identity, metadata, authorization results). Evaluators read/write from this structure.

### Key Packages

- `api/v1beta2` & `api/v1beta3`: AuthConfig CRD definitions
- `controllers/`: Kubernetes controllers for AuthConfig and Secret reconciliation
- `pkg/service/`: gRPC and HTTP authorization service implementations
- `pkg/auth/`: Core authentication logic and credential extraction
- `pkg/evaluators/`: Implementations of auth pipeline phases:
  - `evaluators/identity/`: Authentication evaluators (JWT, API key, OAuth2, etc.)
  - `evaluators/authorization/`: Authorization evaluators (OPA, pattern-matching, K8s SAR, etc.)
  - `evaluators/metadata/`: External metadata fetchers (HTTP, OIDC UserInfo, UMA)
  - `evaluators/response/`: Dynamic response builders (wristbands, JSON injection)
- `pkg/index/`: AuthConfig index management
- `pkg/metrics/`: Prometheus metrics
- `pkg/trace/`: OpenTelemetry tracing

### Main Entry Point

`main.go` defines a Cobra CLI with three commands:
- `authorino server`: Runs the authorization server (primary mode)
- `authorino webhooks`: Runs validation webhooks
- `authorino version`: Prints version info

The server command starts:
- gRPC auth service (port 50051, implements Envoy external auth protocol)
- HTTP auth service (port 5001, raw HTTP interface)
- OIDC server (port 8083, for Festival Wristband token discovery)
- Kubernetes reconciliation managers (AuthConfig & Secret controllers)

## AuthConfig Custom Resource

AuthConfigs declare the protection rules for services. Key sections:

```yaml
spec:
  hosts: []                 # Host names this config applies to
  when: []                  # Top-level conditions
  authentication: {}        # Identity verification (required, 1+ configs)
  metadata: {}             # External data fetching (optional)
  authorization: {}        # Policy enforcement (optional)
  response:                # Dynamic responses (optional)
    success:
      headers: {}          # HTTP headers to inject
      dynamicMetadata: {}  # Envoy dynamic metadata
  callbacks: {}            # HTTP callbacks (optional)
```

## Working with the Codebase

### Host Lookup

Authorino reads `Attributes.Http.Host` from Envoy's CheckRequest or `host` from `ContextExtensions`. It supports:
- Exact host matching
- Wildcard subdomain matching (e.g., `*.pets.com`)
- Host collision prevention (can be disabled with `--allow-superseding-host-subsets`)

### Reconciliation & Status Updates

- All replicas reconcile the same resources matching `--auth-config-label-selector` and `--secret-label-selector`
- One replica is elected leader for status updates
- The index is updated when AuthConfigs or related Secrets change

### Common Development Patterns

**Adding a new evaluator**:
1. Implement the evaluator interface in the appropriate `pkg/evaluators/` subdirectory
2. Add CRD spec in `api/v1beta3/auth_config_types.go`
3. Update controller reconciliation logic in `controllers/auth_config_controller.go`
4. Add tests following existing patterns in the evaluator's package

**Caching**:
- OIDC/UMA configs are cached at reconciliation-time
- JWKs are cached and auto-refreshed based on `spec.authentication.jwt.ttl`
- Rego policies are precompiled at reconciliation-time
- Each evaluator can use `spec..cache` for instance-level caching

### Testing

Tests use envtest (Kubernetes control plane components) for controller tests. Set `KUBEBUILDER_ASSETS` to the envtest binaries path (handled by `make test`).

Mock generation example:
```bash
./bin/mockgen -source=pkg/auth/auth.go -destination=pkg/auth/mocks/mock_auth.go
```

### Logging

- Use structured logging via `logr.Logger`
- Sensitive data must be redacted or logged at debug level (`V(1)`)
- Include trace IDs for request correlation

### Important Configuration Flags

Server command flags:
- `--watch-namespace`: Limit to specific namespace (cluster-wide if empty)
- `--auth-config-label-selector`: Filter AuthConfigs by labels (sharding)
- `--secret-label-selector`: Filter Secrets (default: `authorino.kuadrant.io/managed-by=authorino`)
- `--timeout`: Server timeout in milliseconds
- `--ext-auth-grpc-port`: gRPC service port (default: 50051)
- `--ext-auth-http-port`: HTTP service port (default: 5001)
- `--evaluator-cache-size`: Cache size per evaluator in MB
- `--deep-metrics-enabled`: Enable detailed per-evaluator metrics

## API Versions

The project maintains two API versions:
- `v1beta2`: Legacy version (in `api/v1beta2/`)
- `v1beta3`: Current version (in `api/v1beta3/`)

Both are registered in the scheme and controllers handle both versions.

## Dependencies

Built with:
- Go 1.25.5
- controller-runtime v0.16.3
- Kubernetes client-go v0.28.3
- Envoy go-control-plane v1.32.4
- OPA v1.4.0
- CEL (Common Expression Language) for dynamic expressions
