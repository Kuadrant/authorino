# CEL Validation Tests

This directory contains CEL (Common Expression Language) validation tests for Authorino AuthConfig CRDs. These tests verify that CEL validation rules defined in the CRD schemas work correctly by attempting to create resources via the Kubernetes API.

## Overview

The tests use [envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest) to spin up a real Kubernetes API server with the AuthConfig CRDs installed, then attempt to create AuthConfig resources with various valid and invalid configurations.

## Test Structure

Each version directory under `tests/cel/` contains:
- **`main_test.go`**: Sets up the envtest environment, installs CRDs, and provides shared test infrastructure
- **`authconfig_test.go`**: Tests CEL validation rules for AuthConfig

## Running the Tests

### Prerequisites

The tests require:
- Go 1.25+
- `controller-gen` tool (for CRD generation)
- `envtest` binaries (downloaded automatically by the test setup)

### Run Tests

From the repository root:

```bash
# Run all CEL validation tests
make test-cel

# Or run directly with go test
go test ./tests/cel/... -v

# Run with specific envtest binaries (e.g., for Kubernetes 1.28.3)
KUBEBUILDER_ASSETS=$(bin/setup-envtest use -p path 1.28.3) go test ./tests/cel/... -v

# Run with a specific Kubernetes version
K8S_VERSION=1.28.0 go test ./tests/cel/... -v

# Run against a real cluster (instead of envtest)
KUBECONFIG=~/.kube/config go test ./tests/cel/... -v
```

### Run Specific Test

```bash
# Run only v1beta3 tests
go test ./tests/cel/v1beta3/... -v

# Run only the KubernetesSubjectAccessReview validation tests
go test ./tests/cel/... -v -run TestKubernetesSubjectAccessReviewCELValidation

# Run a specific test case
go test ./tests/cel/v1beta3/... -v -run TestKubernetesSubjectAccessReviewCELValidation/valid_-_user_specified
```

## Test Output

Successful test run:
```text
=== RUN   TestKubernetesSubjectAccessReviewCELValidation
=== RUN   TestKubernetesSubjectAccessReviewCELValidation/valid_-_user_specified
=== RUN   TestKubernetesSubjectAccessReviewCELValidation/valid_-_groups_specified_(static_list)
=== RUN   TestKubernetesSubjectAccessReviewCELValidation/invalid_-_no_user,_groups,_or_authorizationGroups
...
--- PASS: TestKubernetesSubjectAccessReviewCELValidation (2.15s)
PASS
```

Failed validation (expected):
```text
=== RUN   TestKubernetesSubjectAccessReviewCELValidation/invalid_-_no_user,_groups,_or_authorizationGroups
    authconfig_sar_test.go:XXX: Got expected validation error:
        AuthConfig.authorino.kuadrant.io "test-sar-1234567890" is invalid:
        spec.authorization.k8s-sar.kubernetesSubjectAccessReview: Invalid value: "object":
        At least one of user, groups, or authorizationGroups must be specified
--- PASS: TestKubernetesSubjectAccessReviewCELValidation/invalid_-_no_user,_groups,_or_authorizationGroups
```

## Environment Variables

- **`KUBECONFIG`**: Path to kubeconfig file. If set, tests run against a real cluster instead of envtest
- **`K8S_VERSION`**: Kubernetes version for envtest (e.g., `1.28.0`). Defaults to latest GA version
- **`ENVTEST_K8S_VERSION`**: Alternative name for `K8S_VERSION`

## Adding New Tests

To add new CEL validation tests:

1. **Add the CEL validation rule** to the CRD type in `api/v1beta3/auth_config_types.go` (or `api/v1beta2/` for v1beta2):
   ```go
   // +kubebuilder:validation:XValidation:rule="your.cel.expression",message="Validation error message"
   type YourSpec struct {
       // ...
   }
   ```

2. **Regenerate CRDs**:
   ```bash
   make manifests
   ```

3. **Add test cases** to the appropriate version's `authconfig_test.go` file (e.g., `tests/cel/v1beta3/authconfig_test.go`):
   ```go
   func TestYourCELValidation(t *testing.T) {
       ctx := context.Background()
       baseConfig := YourValidConfig{}

       testCases := []struct {
           desc       string
           mutate     func(cfg *YourConfig)
           wantErrors []string
       }{
           {
               desc: "valid case",
               mutate: func(cfg *YourConfig) {
                   // mutations
               },
           },
           {
               desc: "invalid case",
               mutate: func(cfg *YourConfig) {
                   // mutations that violate CEL rule
               },
               wantErrors: []string{"expected error message"},
           },
       }

       for _, tc := range testCases {
           t.Run(tc.desc, func(t *testing.T) {
               config := baseConfig.DeepCopy()
               config.Name = fmt.Sprintf("test-%v", time.Now().UnixNano())

               if tc.mutate != nil {
                   tc.mutate(config)
               }

               err := k8sClient.Create(ctx, config)

               if (len(tc.wantErrors) != 0) != (err != nil) {
                   t.Fatalf("Unexpected validation result")
               }

               if err != nil {
                   for _, wantError := range tc.wantErrors {
                       if !celErrorStringMatches(err.Error(), wantError) {
                           t.Errorf("Missing expected error: %s", wantError)
                       }
                   }
               } else {
                   _ = k8sClient.Delete(ctx, config)
               }
           })
       }
   }
   ```

## Troubleshooting

### envtest fails to download binaries

If you see errors about downloading envtest binaries:

```bash
# Manually download binaries
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
setup-envtest use 1.28.0

# Set the path
export KUBEBUILDER_ASSETS=$(setup-envtest use -p path 1.28.0)
```

### CRD validation not working

Make sure you've regenerated the CRDs after adding CEL validation rules:

```bash
make manifests
```

### Tests fail with "scheme not registered"

Ensure the scheme is properly registered in `main_test.go`:

```go
utilruntime.Must(v1beta3.AddToScheme(scheme))
```
