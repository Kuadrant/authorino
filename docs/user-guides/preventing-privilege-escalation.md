# User guide: Preventing namespace-to-cluster privilege escalation (AuthConfigs)

Two fields on `AuthConfig` resources reach beyond the namespace they live in: `spec.authentication.*.apiKey.allNamespaces` and `spec.authentication.*.x509.allNamespaces`. When either is set to `true`, cluster-wide Authorino instances will look up the API-key / trusted-certificate `Secret`s across **every** namespace in the cluster, so anyone allowed to create `AuthConfig`s in a single namespace can use Authorino's elevated privileges to quietly reach secrets at cluster scope.
This issue does not affect namespaced Authorino instances, but it can be a problem in multi-tenant, shared Authorino instances (aka: cluster-wide deployments).

The [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) below closes that gap. It blocks *enabling* those fields unless the user has been given a special permission for them, and you hand that permission only to the subjects that need it to do their job.

The policy:

<table>
  <thead>
    <tr>
      <th>Policy</th>
      <th>Resource</th>
      <th>Denies</th>
      <th>ClusterRole required to allow</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="2"><code>authconfig-restrict-all-namespaces</code></td>
      <td rowspan="2"><code>authconfigs</code></td>
      <td><code>spec.authentication.*.apiKey.allNamespaces: true</code></td>
      <td><code>set-apikey-all-namespaces</code> on <code>authconfigs</code></td>
    </tr>
    <tr>
      <td><code>spec.authentication.*.x509.allNamespaces: true</code></td>
      <td><code>set-x509-all-namespaces</code> on <code>authconfigs</code></td>
    </tr>
  </tbody>
</table>

Follow the steps below: create the Roles that grant those permissions, bind the roles to specific SAs and Users, then apply the policy.

## 1. Create the Roles

```sh
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-set-apikey-all-namespaces
rules:
  - apiGroups: ["authorino.kuadrant.io"]
    resources: ["authconfigs"]
    verbs: ["set-apikey-all-namespaces"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-set-x509-all-namespaces
rules:
  - apiGroups: ["authorino.kuadrant.io"]
    resources: ["authconfigs"]
    verbs: ["set-x509-all-namespaces"]
EOF
```

## 2. Grant the access to the restricted fields

Grant access to your own ServiceAccounts and Users. Use the RoleBindings below as a template. Replace the placeholders (`<sa-name>`, `<namespace-of-sa>`, `<authconfig-namespace>`) with the appropriate values.

```sh
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-set-apikey-all-namespaces
  namespace: <authconfig-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-set-apikey-all-namespaces
subjects:
  - kind: ServiceAccount
    name: <sa-name>
    namespace: <namespace-of-sa>
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-set-x509-all-namespaces
  namespace: <authconfig-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-set-x509-all-namespaces
subjects:
  - kind: ServiceAccount
    name: <sa-name>
    namespace: <namespace-of-sa>
EOF
```

## 3. Create the ValidatingAdmissionPolicy (VAP)

```sh
kubectl apply -f - <<'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: authconfig-restrict-all-namespaces
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["authorino.kuadrant.io"]
        apiVersions: ["v1beta3"]
        operations: ["CREATE", "UPDATE"]
        resources: ["authconfigs"]
  variables:
    - name: isExemptApiKey
      expression: "authorizer.requestResource.check('set-apikey-all-namespaces').allowed()"
    - name: isExemptX509
      expression: "authorizer.requestResource.check('set-x509-all-namespaces').allowed()"
    - name: wantsApiKeyAllNamespaces
      expression: "has(object.spec.authentication) && object.spec.authentication.exists(k, has(object.spec.authentication[k].apiKey) && has(object.spec.authentication[k].apiKey.allNamespaces) && object.spec.authentication[k].apiKey.allNamespaces)"
    - name: wantsX509AllNamespaces
      expression: "has(object.spec.authentication) && object.spec.authentication.exists(k, has(object.spec.authentication[k].x509) && has(object.spec.authentication[k].x509.allNamespaces) && object.spec.authentication[k].x509.allNamespaces)"
    # hadApiKeyAllNamespaces / hadX509AllNamespaces capture whether the field was already
    # enabled before this request (oldObject is null on CREATE). They let the policy
    # restrict only newly enabling allNamespaces, so a subject without the permission can
    # still edit unrelated fields of an object that already has it enabled.
    - name: hadApiKeyAllNamespaces
      expression: "oldObject != null && has(oldObject.spec.authentication) && oldObject.spec.authentication.exists(k, has(oldObject.spec.authentication[k].apiKey) && has(oldObject.spec.authentication[k].apiKey.allNamespaces) && oldObject.spec.authentication[k].apiKey.allNamespaces)"
    - name: hadX509AllNamespaces
      expression: "oldObject != null && has(oldObject.spec.authentication) && oldObject.spec.authentication.exists(k, has(oldObject.spec.authentication[k].x509) && has(oldObject.spec.authentication[k].x509.allNamespaces) && oldObject.spec.authentication[k].x509.allNamespaces)"
  validations:
    - expression: "!variables.wantsApiKeyAllNamespaces || variables.hadApiKeyAllNamespaces || variables.isExemptApiKey"
      message: "apiKey allNamespaces: true (cluster-wide secret lookup) can only be enabled by a subject granted the 'set-apikey-all-namespaces' permission on authconfigs"
      reason: Forbidden
    - expression: "!variables.wantsX509AllNamespaces || variables.hadX509AllNamespaces || variables.isExemptX509"
      message: "x509 allNamespaces: true (cluster-wide secret lookup) can only be enabled by a subject granted the 'set-x509-all-namespaces' permission on authconfigs"
      reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: authconfig-restrict-all-namespaces-binding
spec:
  policyName: authconfig-restrict-all-namespaces
  validationActions: ["Deny"]
EOF
```

> [!WARNING]
> The policy restricts **newly enabling** a restricted field, not merely having it enabled. On **create**, any resource that sets a restricted field (`apiKey.allNamespaces: true` or `x509.allNamespaces: true`) is **rejected** unless the requesting subject holds the matching permission. On **update**, only the transition from unset/`false` to `true` is blocked: a subject without the permission can still edit **unrelated** fields of — and can **disable** the field on — a resource that already has it enabled. Resources that already enable a restricted field when the policy is applied are therefore **not** retroactively broken. Newly enabling the field always requires the permission, so grant the required Roles and RoleBindings (steps 1–2) to the subjects that need it.

## 4. Verifying the VAP

### A normal user is blocked

Try to create resources that break the rules. Run these as a regular user (one *without* the permissions) and both should be **rejected**:

> [!NOTE]
> Do not run these as a cluster administrator. Anything with wildcard access (`verbs: ["*"]`) — which cluster admins have — satisfies the `set-apikey-all-namespaces` / `set-x509-all-namespaces` checks and is treated as exempt, so the request would be **allowed** and a real cluster-wide secret lookup enabled. Use an ordinary user (or `--as=<unauthorized-subject>`) to see the policy block.

```sh
# AuthConfig with apiKey allNamespaces: true — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-all-namespaces-1
  namespace: <namespace>
spec:
  hosts:
    - test-denied.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: true
        selector:
          matchLabels:
            group: friends
EOF
```

```sh
# AuthConfig with x509 allNamespaces: true — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-x509-1
  namespace: <namespace>
spec:
  hosts:
    - test-x509-denied.example.com
  authentication:
    mtls-clients:
      x509:
        allNamespaces: true
        selector:
          matchLabels:
            group: friends
EOF
```

You should get an error like this instead of the resource being created:

```text
... is forbidden: ValidatingAdmissionPolicy 'authconfig-restrict-all-namespaces' ... denied request: apiKey allNamespaces: true (cluster-wide secret lookup) can only be enabled by a subject granted the 'set-apikey-all-namespaces' permission on authconfigs
```

### A permitted subject is allowed

Now run the same requests as a subject that holds the matching permission (granted in steps 1–2). Both should be **admitted**. Replace `<authorized-subject>` with the subject you granted the permission to (for example, `system:serviceaccount:<namespace>:<sa>`):

```sh
# AuthConfig with apiKey allNamespaces: true, as a subject granted 'set-apikey-all-namespaces' — should be ALLOWED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-all-namespaces-2
  namespace: <namespace>
spec:
  hosts:
    - test-allowed.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: true
        selector:
          matchLabels:
            group: friends
EOF
```

```sh
# AuthConfig with x509 allNamespaces: true, as a subject granted 'set-x509-all-namespaces' — should be ALLOWED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-x509-2
  namespace: <namespace>
spec:
  hosts:
    - test-x509-allowed.example.com
  authentication:
    mtls-clients:
      x509:
        allNamespaces: true
        selector:
          matchLabels:
            group: friends
EOF
```

### Resources without the restricted fields are always allowed

The policy only looks at the restricted fields. A resource that leaves them unset (or `false`) is admitted for **any** subject, whether or not it holds a permission:

```sh
# AuthConfig with apiKey allNamespaces: false — should be ALLOWED even for an unauthorized subject
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-namespaced-1
  namespace: <namespace>
spec:
  hosts:
    - test-namespaced.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: false
        selector:
          matchLabels:
            group: friends
EOF
```

### Updates are re-checked, not just creates

Because the policy matches `UPDATE` as well as `CREATE`, it re-evaluates on every change — but it only restricts *newly enabling* a restricted field. A subject without the permission can edit **unrelated** fields of a resource whether or not the field is already enabled, and can **disable** it; it is blocked only when it tries to switch the field from off to on. Using the namespaced AuthConfig created above:

```sh
# Change an unrelated field (the apiKey selector) on the namespaced AuthConfig — should be ALLOWED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-namespaced-1
  namespace: <namespace>
spec:
  hosts:
    - test-namespaced.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: false
        selector:
          matchLabels:
            group: family
EOF
```

```sh
# Flip the same AuthConfig to apiKey allNamespaces: true — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-namespaced-1
  namespace: <namespace>
spec:
  hosts:
    - test-namespaced.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: true
        selector:
          matchLabels:
            group: family
EOF
```

An object that **already** has a restricted field enabled can likewise be updated by a subject without the permission, as long as the field stays enabled. Using `policy-all-namespaces-2` (created by the authorized subject above, with `apiKey.allNamespaces: true`):

```sh
# Edit an unrelated field (the host) while leaving apiKey allNamespaces: true unchanged — should be ALLOWED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-all-namespaces-2
  namespace: <namespace>
spec:
  hosts:
    - test-allowed-updated.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: true
        selector:
          matchLabels:
            group: friends
EOF
```

### Permissions bound with a RoleBinding are namespace-scoped

The exemption check runs against the namespace of the resource being admitted. If you grant the permission with a `RoleBinding` (rather than a `ClusterRoleBinding`), the subject is exempt only in that namespace.

```sh
# Subject granted 'set-apikey-all-namespaces' via a RoleBinding in <namespace-a> — should be ALLOWED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-all-namespaces-3
  namespace: <namespace-a>
spec:
  hosts:
    - test-rb-a.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: true
        selector:
          matchLabels:
            group: friends
EOF
```

```sh
# Same subject, same request, in <namespace-b> where it has no binding — should be DENIED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: policy-all-namespaces-3
  namespace: <namespace-b>
spec:
  hosts:
    - test-rb-b.example.com
  authentication:
    api-key-users:
      apiKey:
        allNamespaces: true
        selector:
          matchLabels:
            group: friends
EOF
```
