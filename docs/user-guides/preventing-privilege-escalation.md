# User guide: Preventing namespace-to-cluster privilege escalation (AuthConfigs)

Two fields on `AuthConfig` resources reach beyond the namespace they live in: `spec.authentication.*.apiKey.allNamespaces` and `spec.authentication.*.x509.allNamespaces`. When either is set to `true`, cluster-wide Authorino instances will look up the API-key / trusted-certificate `Secret`s across **every** namespace in the cluster, so anyone allowed to create `AuthConfig`s in a single namespace can use Authorino's elevated privileges to quietly reach secrets at cluster scope.
This issue does not affect namespaced Authorino instances, but it can be a problem in multi-tenant, shared Authorino instances (aka: cluster-wide deployments).

The [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) below closes that gap. It blocks every create and update of an `AuthConfig` that has one of those fields enabled, unless the user has been given a special permission for it, and you hand that permission only to the subjects that need it to do their job.

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
  validations:
    - expression: "!variables.wantsApiKeyAllNamespaces || variables.isExemptApiKey"
      message: "apiKey allNamespaces: true (cluster-wide secret lookup) requires the 'set-apikey-all-namespaces' permission on authconfigs; a subject without it can neither create nor modify an AuthConfig that has the field enabled"
      reason: Forbidden
    - expression: "!variables.wantsX509AllNamespaces || variables.isExemptX509"
      message: "x509 allNamespaces: true (cluster-wide secret lookup) requires the 'set-x509-all-namespaces' permission on authconfigs; a subject without it can neither create nor modify an AuthConfig that has the field enabled"
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
> The policy restricts **having** a restricted field enabled, not merely the act of enabling it. Any request — **create** or **update** — whose resulting resource sets `apiKey.allNamespaces: true` or `x509.allNamespaces: true` is **rejected** unless the requesting subject holds the matching permission. In practice this makes an `AuthConfig` that enables a restricted field **read-only** for every subject that lacks the permission: they cannot edit even unrelated fields such as `hosts` or `authorization`. They *can* still submit an update that **disables** the field, and resources that leave the restricted fields unset or `false` are unaffected. Grant the Roles and RoleBindings from steps 1–2 to every subject that has to write these resources, **including controllers and GitOps agents** that reconcile them.
>
> The policy deliberately does not grandfather resources that already enable a restricted field. Editing the *rest* of the spec is enough to abuse the cluster-wide lookup: the resolved identity of an `apiKey` authentication is the matched `Secret` itself, data included, and `spec.callbacks` and `spec.response` can read `auth.identity`. A subject able to edit an already cluster-wide `AuthConfig` could therefore attach a callback to a destination it controls and have every successful request forward the caller's `Secret`, from any namespace in the cluster, without ever touching `allNamespaces` or its `selector`.
>
> Existing resources are not deleted or rewritten when you apply the policy, and Authorino keeps enforcing them. Only subsequent writes to them are gated.

Before rolling the policy out on a live cluster, list the resources that will become restricted, so you know which subjects need the permission from steps 1–2:

```sh
kubectl get authconfigs -A -o json | jq -r '
  .items[]
  | select(
      [.spec.authentication[]? | (.apiKey.allNamespaces // false) or (.x509.allNamespaces // false)]
      | any
    )
  | "\(.metadata.namespace)/\(.metadata.name)"'
```

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
... is forbidden: ValidatingAdmissionPolicy 'authconfig-restrict-all-namespaces' ... denied request: apiKey allNamespaces: true (cluster-wide secret lookup) requires the 'set-apikey-all-namespaces' permission on authconfigs; a subject without it can neither create nor modify an AuthConfig that has the field enabled
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

Because the policy matches `UPDATE` as well as `CREATE`, it re-evaluates on every change, against the resource as it would be **after** the update. A subject without the permission can freely edit a resource that leaves the restricted fields off, but cannot submit any update whose result has one of them on. Using the namespaced AuthConfig created above:

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

An object that **already** has a restricted field enabled is closed to subjects without the permission, even for edits that do not touch the field. Using `policy-all-namespaces-2` (created by the authorized subject above, with `apiKey.allNamespaces: true`):

```sh
# Edit an unrelated field (the host) while leaving apiKey allNamespaces: true unchanged — should be DENIED
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

The one update such a subject can still make is one that turns the restricted field **off**, since the resulting resource no longer enables the cluster-wide lookup:

```sh
# Disable apiKey allNamespaces on the same resource — should be ALLOWED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
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
        allNamespaces: false
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
