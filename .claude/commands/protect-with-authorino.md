---
description: Protect a service with Authorino by generating and applying an AuthConfig CR
---

You are an expert at working with Authorino, a Kubernetes-native authorization service. Your task is to protect a service by creating and applying an AuthConfig custom resource with the specified authentication and authorization rules.

## Task Overview

1. **Check Kubernetes cluster**: Verify that a Kubernetes cluster is accessible via `kubectl`
2. **Check Authorino installation**: Determine if Authorino is installed and running in the cluster
3. **Install Authorino if needed**: If not installed, use the Makefile targets to install and deploy Authorino from a local build
4. **Parse the arguments**: Extract the hostname, authentication rules, and authorization rules from the user's input
5. **Generate AuthConfig CR**: Create a valid AuthConfig YAML manifest based on the parsed arguments
6. **Apply to cluster**: Use `kubectl apply` to deploy the AuthConfig to the cluster

## Input Format

The user will provide arguments in this format:
```
/protect-with-authorino <hostname> "<authentication-rules>" "<authorization-rules>"
```

**Example:**
```
/protect-with-authorino talker-api.127.0.0.1.nip.io "oidc authentication (issuer url: http://keycloak.keycloak.svc.cluster.local/realms/my-realm)" "'aud' jwt claim must be equal to 'talker-api'"
```

## Authentication Rules Parsing

Parse natural language authentication descriptions and map them to AuthConfig authentication specs:

- **"oidc authentication"** or **"jwt authentication"** with **"issuer url: <url>"** → Use `jwt.issuerUrl`
- **"api key"** with selector/labels → Use `apiKey.selector`
- **"kubernetes token review"** → Use `kubernetesTokenReview`
- **"oauth2 token introspection"** with endpoint → Use `oauth2Introspection`
- **"anonymous access"** → Use `anonymous: {}`

## Authorization Rules Parsing

Parse natural language authorization descriptions and map them to AuthConfig authorization specs:

- **"jwt claim"** checks (e.g., "'aud' must be equal to 'value'") → Use `patternMatching` with CEL predicates like `auth.identity.aud == 'value'`
- **"opa policy"** → Use `opa.rego` with the provided Rego code
- **"kubernetes rbac"** → Use `kubernetesSubjectAccessReview`
- **"pattern matching"** → Use `patternMatching.patterns` with predicates
- **"all requests allowed"** or no authorization rules → Omit authorization section

## AuthConfig Structure Reference

Use the v1beta3 API version. Structure:

```yaml
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: <generated-name>
  namespace: <target-namespace>
spec:
  hosts:
  - <hostname>

  authentication:
    <auth-name>:
      jwt:
        issuerUrl: <url>
      # OR apiKey, kubernetesTokenReview, oauth2Introspection, etc.

  authorization:  # Optional
    <authz-name>:
      patternMatching:
        patterns:
        - predicate: <cel-expression>
      # OR opa, kubernetesSubjectAccessReview, etc.
```

## Implementation Steps

### Step 1: Check Kubernetes Cluster
```bash
kubectl cluster-info
```
- If this fails, inform the user that no Kubernetes cluster is accessible

### Step 2: Check Authorino Installation
```bash
kubectl get authorino/authorino -n authorino -A 2>/dev/null
```
- If Authorino deployment exists and is running, proceed to Step 4
- If not found, proceed to Step 3

### Step 3: Install Authorino (if needed)
Use the Makefile targets from the repository:
```bash
make install-operator install local-build namespace deploy NAMESPACE=authorino FF=1
```
This will:
- Install the Authorino Operator to the current Kubernetes context
- Build and load the Authorino image
- Install the Authorino operator
- Deploy Authorino instance
- Deploy test apps (including Keycloak if needed)

Wait for installation to complete before proceeding.

### Step 4: Parse Arguments

Extract from the user's input:
- **Hostname**: First positional argument
- **Authentication rules**: Second argument (quoted string)
- **Authorization rules**: Third argument (quoted string, optional)

### Step 5: Generate AuthConfig YAML

Create a valid AuthConfig manifest:
- **metadata.name**: Generate from hostname (e.g., `talker-api` from `talker-api.127.0.0.1.nip.io`)
- **metadata.namespace**: Use `authorino` or the namespace where Authorino is installed
- **spec.hosts**: Array with the provided hostname
- **spec.authentication**: Map parsed authentication rules to appropriate authentication specs
- **spec.authorization**: Map parsed authorization rules to appropriate authorization specs (if provided)

### Step 6: Apply AuthConfig

```bash
kubectl apply -f <authconfig-file>.yaml
```

Verify the AuthConfig was created:
```bash
kubectl get authconfig -n authorino
```

Check the AuthConfig status:
```bash
kubectl get authconfig <name> -n authorino -o yaml
```

## Important Notes

- **Only use `bash` and `kubectl` tools** - do not use other tools unless absolutely necessary
- **Always include `FF=1`** for all make target executions that include the `deploy` target, such as `make local-setup`, otherwise Claude CLI will hang waiting for an impossible user input
- **Generate descriptive names** for authentication and authorization rules (e.g., `oidc-keycloak`, `check-aud-claim`)
- **Use CEL expressions** for pattern matching predicates (e.g., `auth.identity.aud == 'talker-api'`)
- **Handle errors gracefully** - if cluster setup fails, provide clear error messages
- **Validate the AuthConfig** - ensure it's in Ready state before finishing
- **Provide next steps** - tell the user how to test the protected service

## Example Output

After successful execution, provide:
1. Confirmation that Authorino is installed and running
2. The generated AuthConfig YAML (show it to the user)
3. Confirmation that the AuthConfig was applied successfully
4. Status of the AuthConfig (Ready/NotReady)
5. Instructions on how to test (e.g., port-forward commands, curl examples)

## Error Handling

- **No cluster**: Prompt user to ensure `kubectl` is configured or offer to create a local Kind cluster
- **Authorino installation fails**: Show error logs and suggest manual troubleshooting
- **Invalid AuthConfig**: Show validation errors from Kubernetes API
- **AuthConfig not ready**: Show the status conditions and suggest fixes

Remember: Be intelligent about parsing natural language - use context clues and common patterns. If the user's input is ambiguous, make reasonable assumptions and document them in the generated AuthConfig.
