# Welcome to Authorino!

Authorino is an AuthN/AuthZ broker that implements [Envoy’s external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) gRPC protocol. It adds protection to your cloud-native APIs with:
- User authentication (OIDC, user/passwd, mTLS)
- Ad-hoc metadata addition to the authorization payload (user info, resource metadata, web hooks)
- Authorization policy enforcement (built-in and external authorization services, JWT claims, OPA, Keycloak)

Authorino complies with the [3scale Ostia architecture](https://github.com/3scale/ostia).

**Current stage:** Proof of Concept

## How it works

<!--
  "API consumer" -> Envoy : 1. HTTP request
  Envoy -> Authorino : 2. gRPC
  Authorino -> Authorino : 3. Verify identity
  Authorino -> Authorino : 4. Add metadata
  Authorino -> Authorino : 5. Enforce policies
  Authorino -> Envoy : 6. OK
  Envoy -> Upstream : 7. HTTP request
  Upstream -> "API consumer" : 8. HTTP response
-->
```
     ┌────────────┐          ┌─────┐          ┌─────────┐               ┌────────┐
     │API consumer│          │Envoy│          │Authorino│               │Upstream│
     └─────┬──────┘          └──┬──┘          └────┬────┘               └───┬────┘
           │  1. HTTP request   │                  │                        │
           │ ──────────────────>│                  │                        │
           │                    │     2. gRPC      │                        │
           │                    │─────────────────>│                        │
           │                    │                  │                        │
           │                    │                  ────┐                    │
           │                    │                      │ 3. Verify identity │
           │                    │                  <───┘                    │
           │                    │                  │                        │
           │                    │                  ────┐                    │
           │                    │                      │ 4. Add metadata    │
           │                    │                  <───┘                    │
           │                    │                  │                        │
           │                    │                  ────┐
           │                    │                      │ 5. Enforce policies
           │                    │                  <───┘
           │                    │      6. OK       │                        │
           │                    │<─────────────────│                        │
           │                    │                  │                        │
           │                    │              7. HTTP request              │
           │                    │───────────────────────────────────────────>
           │                    │                  │                        │
           │                    │   8. HTTP response                        │
           │ <───────────────────────────────────────────────────────────────
     ┌─────┴──────┐          ┌──┴──┐          ┌────┴────┐               ┌───┴────┐
     │API consumer│          │Envoy│          │Authorino│               │Upstream│
     └────────────┘          └─────┘          └─────────┘               └────────┘
```

1. An _API consumer_ sends a request to the _Envoy_ endpoint, including the `Authorization` and `Host` HTTP headers
2. The Envoy proxy establishes fast gRPC connection with _Authorino_, carrying data of the HTTP request
3. **Identity verification step** - Authorino verifies the identity of the the original requestor, where at least one authentication method/identity provider should answer
4. **Ad-hoc authorization metadata step** - Authorino integrates external sources to add metadata to the authorization payload, such as user info, attributes of the requested resource and payload-mutating web hooks
5. **Policy enforcement step** - Authorino dispatches authorization policy evaluation to one or more configured Policy Decision Points (PDP)
6. Authorino and Envoy settle the authorization protocol with either a `200 OK`, `403 Forbidden` or `404 Not found` response
7. If authorized, Envoy redirects to the requested _Upstream_
8. The Upstream serves the requested resource

The three Authorino's core steps are depicted in the diagram, respectively, as 3, 4 and 5 in the overall flow. These steps rely on well-established industry standards and protocols, such as [OpenID Connect (OIDC)](https://openid.net/connect/), [User-Managed Access (UMA)](https://docs.kantarainitiative.org/uma/rec-uma-core.html), [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) and [mutual Transport Layer Security (mTLS)](https://www.rfc-editor.org/rfc/rfc8705.html), and enable API developers to add API security through configuration by mixing and combining settings to external services that implement such standards. Authorino enforces authentication and authorization to the API requests based on that single file configuration.

_Identity verification_ can be, for example, verifying a provided JSON Web Token (JWT) previously issued by an OIDC-compliant authentication server and provided in the `Authorization` header of the HTTP request. Authorino will auto-discover the OIDC configuration from the settings, verify the token signature and validity in time.

_Ad-hoc authorization metadata_ can be the fetching of OIDC user info (based on the same configuration used for the identity before) and/or about fecthing resource data from a UMA-compliant server that knows about the resources.

_Policy enforcement_ is where Authorino connects to one or more authorization policy evaluation services (or Policy Decision Points (PDP)) that will ultimately decide on whether the HTTP request should be authorized or not, given the known gathered information about the identity, the origin of the request, the requested resource and, of course, the configured policies.

_Identity verification_ and _Ad-hoc authorization metadata_ steps add info for the _Policy enforcement_, meaning API developers can write authorization policies trusting on information available about the requestor's identity (a decoded JWT, for example) and on the metadata added ad-hoc to the authorization payload (e.g. specific user info or data about the requested resource). Of course, if Authorino fails to verify the user's identity in the _Identity verification_ step, the request is rejected without further development of the other two steps.

## Features

Once ready, Authorino will support at least 3 different authentication methods (i.e., OIDC, user/passwd and mTLS), plus ad-hoc additions to the authorization payload (e.g., user info, resource metadata, web hooks), and combination of multiple authorization services (JWT claims, OPA, Keycloak). Authorino will also handle caching of user credentials, permissions, revocations.

Here's a list of features related to each of Authorino's 3 core steps and supporting features.

- Features listed as "PoC" mean they are already implemented and ready to use in the current stage of Authorino, which is still in proof of concept.
- "Planned" are the features that are part of the original proposal of Authorino but not yet in PoC.
- "In analysis" are suggested features that may require extra effort to be implemented and therefore are still being analyzed regarding viability or design.

<table>
  <thead>
    <tr>
      <th colspan="2">Feature</th>
      <th>Stage</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="4">Identity verification</td>
      <td>OpenID Connect (OIDC)</td>
      <td>PoC</td>
    </tr>
    <tr>
      <td>Basic auth (user/passwd)</td>
      <td>Planned</td>
    </tr>
    <tr>
      <td>mTLS</td>
      <td>Planned</td>
    </tr>
    <tr>
      <td>HMAC</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="3">Ad-hoc authorization metadata</td>
      <td>OIDC user info</td>
      <td>PoC</td>
    </tr>
    <tr>
      <td>UMA-protected resource attributes</td>
      <td>PoC</td>
    </tr>
    <tr>
      <td>Web hooks</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="4">Policy enforcement</td>
      <td>OPA inline Rego policies</td>
      <td>PoC</td>
    </tr>
    <tr>
      <td>OPA simple pattern matching</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td>Keycloak (UMA-compliant Authorization API)</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td>JWT claims</td>
      <td>Planned</td>
    </tr>
    <tr>
      <td rowspan="6">Caching</td>
      <td>OIDC and UMA configs</td>
      <td>PoC</td>
    </tr>
    <tr>
      <td>JSON Web Ket Sets (JWKS)</td>
      <td>PoC</td>
    </tr>
    <tr>
      <td>Revoked access tokens</td>
      <td>Planned</td>
    </tr>
    <tr>
      <td>Resource data</td>
      <td>Planned</td>
    </tr>
    <tr>
      <td>Authorization policies</td>
      <td>PoC</td>
    </tr>
    <tr>
      <td>Repeated requests</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td colspan="2">Multitenancy (multiple upstreams)</td>
      <td>PoC</td>
    </tr>
  </tbody>
</table>

#### OpenID Connect (OIDC)

Authorino automatically discovers OIDC configurations for the registered issuers and verifies JSON Web Tokens (JWTs) provided in the `Authorization` header by the API consumers on every request.

Authorino also automatically fetches the JSON Web Key Sets (JWKS) used to verify the JWTs, matching the `kid` stated in the JWT header (i.e., support to easy key rotation).

In general, OIDC confgurations are essencially used in the identity verification and in the ad-hoc authorization metadata steps of Authorino. The decoded JWTs and fetched user info are passed in the authorization payload to the third step, i.e., policy enforcement.

<!--
  Authorino -> "OIDC Issuer" : OIDC discovery
  "OIDC Issuer" -> Authorino : Well-Known config
  Authorino -> "OIDC Issuer" : Req OIDC certs
  "OIDC Issuer" -> Authorino : JWKS
  Authorino -> Authorino : Verify JWT signature
  Authorino -> Authorino : Validate JWT
-->
```
     ┌─────────┐              ┌───────────┐
     │Authorino│              │OIDC Issuer│
     └────┬────┘              └─────┬─────┘
          │     OIDC discovery      │
          │────────────────────────>│
          │    Well-Known config    │
 (cache)  │<────────────────────────│
          │                         │
          │     Req OIDC certs      │
          │────────────────────────>│
          │          JWKS           │
 (cache)  │<────────────────────────│
          │                         │
          ────┐                     │
              │ Verify JWT signature│
          <───┘                     │
          │                         │
          ────┐                     │
              │ Validate JWT        │
          <───┘                     │
     ┌────┴────┐              ┌─────┴─────┐
     │Authorino│              │OIDC Issuer│
     └─────────┘              └───────────┘
```

#### User-Managed Access (UMA)

User-Managed Access (UMA) is an OAuth-based protocol for resource owners to allow other users to access their resources. Since the UMA-compliant server is expected to know about the resources, Authorino includes a client that fetches resource data from the server and adds that as metadata of the authorization payload.

This enables the implementation of Attribute-Based Access Control (ABAC) policies using attributes of the resources. These attributes can be, e.g., the owner of the resource (say, to match with the requestor identity) or any business-level attributes stored in the UMA-compliant server.

A UMA-compliant server can be an external authorization server (e.g., Keycloak) where the protected resources are registered or it can be the upstream API itself (as long as it implements the UMA protocol, with initial authentication by `client_credentials` grant to exchange for a Protected API Token (PAT)).

<!--
  Authorino -> "UMA server" : UMA Discovery
  "UMA server" -> Authorino : Well-Known config
  Authorino -> "UMA server" : Request PAT
  "UMA server" -> Authorino : PAT
  Authorino -> "UMA server" : Query resources (?uri=path)
  "UMA server" -> Authorino : [...resources]
  Authorino -> "UMA server" : GET resource
  "UMA server" -> Authorino : Resource data
-->
```
     ┌─────────┐                 ┌──────────┐
     │Authorino│                 │UMA server│
     └────┬────┘                 └────┬─────┘
          │       UMA Discovery       │
          │───────────────────────────>
          │     Well-Known config     │
 (cache)  │<───────────────────────────
          │                           │
          │        Request PAT        │
          │───────────────────────────>
          │            PAT            │
          │<───────────────────────────
          │                           │
          │Query resources (?uri=path)│
          │───────────────────────────>
          │      [...resources]       │
          │<───────────────────────────
          │                           │
          │       GET resource        │
          │───────────────────────────>
          │       Resource data       │
          │<───────────────────────────
     ┌────┴────┐                 ┌────┴─────┐
     │Authorino│                 │UMA server│
     └─────────┘                 └──────────┘
```

It's important to notice that Authorino does NOT manage resources in the UMA-compliant server. As shown in the flow above, Authorino's UMA client is only to fetch data about the requested resources. Authorino exchanges client credentials for a Protected API Token (PAT), then queries for resources whose URI match the path of the HTTP request (as passed to Authorino by the Envoy proxy) and fecthes data of each macthing resource.

The resources data is added as metadata of the authorization payload and passed in the input for the configured Policy Decision Points (e.g., an OPA authorization service). All resources returned by the UMA-compliant server in the query by URI are passed along. They are available in the PDPs' input as `input.context.metadata.uma => Array`.

#### Open Policy Agent (OPA)

You can model authorization policies in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) and add them as part of the configuration of your protected APIs. Authorino will keep track of changes to the policies and automatically register them to the OPA server.

<!--
  Authorino -> OPA : Register policy
  OPA -> Authorino
  Authorino -> OPA : Get document with input
  OPA -> OPA : Evaluate policy
  OPA -> Authorino : 200 OK
-->
```
           ┌─────────┐                 ┌───┐
           │Authorino│                 │OPA│
           └────┬────┘                 └─┬─┘
                ·                        ·
Boot-time:      │    Register policy     │
                │───────────────────────>│
                │<───────────────────────│
                │                        │
                ·                        ·
Request-time:   │Get document with input │
                │───────────────────────>│
                │                        │
                │                        ────┐
                │                            │ Evaluate policy
                │                        <───┘
                │                        │
                │        200 OK          │
                │<───────────────────────│
           ┌────┴────┐                 ┌─┴─┐
           │Authorino│                 │OPA│
           └─────────┘                 └───┘
```

## Usage

There are 2 main use cases for Authorino:
- A. protecting APIs
- B. protecting resources and scopes of the APIM system

We are currently working on the features to support use case A and, at the same time, planning for soon having Authorino configured and deployed with Red Hat 3scale to support use case B. The latter will allow API providers to configure access control over resources of the API management system in the same fashion they do for their managed APIs.

To use Authorino to protect your APIs with OIDC and OPA, please consider the following requirements and deployment options.

### Requirements

1. At least one upstream API (i.e., the API you want to protect)
2. [Envoy](https://www.envoyproxy.io) proxy managing the HTTP connections to the upstream API and configured with the [External Authorization Filter](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) pointing to Authorino (default port: 50051).
3. For OpenID Connect, an authority that can issue JWTs
4. For UMA-protected resource data, a UMA-compliant server
5. OPA server (default port: 8181)

### Configuring Authorino

Authorino configuration is one YAML file and a couple of environment variables. The structure of the YAML config is something like the following:

```yaml
<upstream-host>:<port>:
  enabled: true/false
  identity: [] # -- list of authentication modes and settings (e.g. `oidc`)
  metadata: [] # -- list of metadata sources (e.g. `userinfo`, `uma`)
  authorization: [] # -- list of PDPs/authorization services and settings (e.g. `opa`)

<other-upstream>:<port>:
  ...
```

A more concrete example of Authorino's `config.yml` file can be found [here](examples/config.yml).

And here's the list of supported environment variables when running Authorino:

|             |                                                                                                       |
| ----------- | ----------------------------------------------------------------------------------------------------- |
| `CONFIG`    | Path to the Authorino YAML config file                                                                |
| `PORT`      | TCP Port that Authorino will listen for gRPC call from the Envoy proxy (default: 50051)               |
| `LOG_LEVEL` | Ruby log level (default: info, [ref](https://ruby-doc.org/stdlib-2.7.1/libdoc/logger/rdoc/Logger/Severity.html)) |

#### Inline Rego policies

For the inline Rego policies in your OPA authorization config, the following objects are available in every document:
- `http_request`: attributes of the HTTP request (e.g., host, path, headers, etc) as passed by Envoy to Authorino
- `identity`: whatever is resolved from the "identity" section of Authorino config, e.g. a decoded JWT of an OIDC authentication
- `metadata`: whatever is resolved from the "metadata" section of Authorino config, e.g. OIDC user info, resource data fetched from a UMA-compliant server
- `path` (Array): just an array of each segment of `http_request.path` to ease writing of rules with comparisson expressions using the requested path.

### Deploy on Docker

```
docker run -v './path/to/config.yml:/usr/src/app/config.yml' -p '50051:50051' 3scale/authorino:latest
```

### Deploy on a Kubernetes cluster

A set of YAMLs exemplifying Authorino deployed to Kubernetes with an OPA PDP sidecar can be found [here](examples/openshift). We recommend storing Authorino's `config.yml` in a `ConfigMap` ([example](examples/openshift/configmap.yaml)). Follow by creating Authorino's `Deployment` and `Service`.

Usually the entire order of deployment goes as follows:
1. Upstream API(s)
2. Policy Decision Point (PDP) service (e.g. OPA server) – can be deployed as an Authorino sidecard as well, like in the example provided
3. Authorino
    - `ConfigMap`
    - `Deployment`
    - `Service`
4. Envoy
    - `ConfigMap`
    - `Deployment`
    - `Service`
    - `Ingress` (and [ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)) or Openshift `Route`

## Check the examples and try it out

Try the [example](examples) on your Docker environment. You'll get the following components out of the box with our docker-compose:

- **Echo API (upstream)**<br/>
    Just a simple rack application that echoes back in a JSON whatever is gets in the request. You can control the response by passing the custom HTTP headers X-Echo-Status and X-Echo-Message (both optional).
- **Envoy proxy**<br/>
    Configured w/ the ext_authz http filter.
- **Authorino**<br/>
    The AuthN/AuthZ broker with [this configuration](examples/config.yml) preloaded.
- **OPA service**<br/>
    An actual Policy Decision Point (PDP) configured in the architecture.
- **Keycloak**<br/>
    To issue OIDC access tokens and to provide ad-hoc resource data for the authorization payload.<br/>
    - Admin console: http://localhost:8080/auth/admin (admin/p)
    - Preloaded realm: **ostia**
    - Preloaded clients:
      - **demo**: to which API consumers delegate access and therefore the one which access tokens are issued to
      - **authorino**: used by Authorino to fetch additional user info with `client_credentials` grant type
      - **pets-api**: used by Authorino to fetch UMA-protected resource data following typical UMA flow
    - Preloaded resources:
      - `/pets`
      - `/pets/1` (owned by user jonh)
      - `/stats`
    - Realm roles:
      - member (default to all users)
      - admin
    - Preloaded users:
      - john/p (member)
      - jane/p (admin)

#### 1. Clone the repo

Start by cloning the repo:

```shell
git clone git@github.com:3scale/authorino.git
```

#### 2. Run the services

```shell
cd authorino/examples
docker-compose up --build -d
```

#### 3. Try out with John (member)

John is a member user of the `ostia` realm in Keycloak. He owns a resource hosted at `/pets/1` and has no access to `/stats`.

```shell
export ACCESS_TOKEN_JOHN=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: echo-api:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/pets -v     # 200 OK
curl -H 'Host: echo-api:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/pets/1 -v   # 200 OK
curl -H 'Host: echo-api:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/stats -v    # 403 Forbidden
```

#### 4. Try out with Jane (admin)

Jane is an admin user of the `ostia` realm in Keycloak. She does not own any resource and has access to `/stats`.

```shell
export ACCESS_TOKEN_JANE=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: echo-api:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/pets -v     # 200 OK
curl -H 'Host: echo-api:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/pets/1 -v   # 403 Forbidden
curl -H 'Host: echo-api:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/stats -v    # 200 OK
```

#### 5. Shut down and clean up
```
docker-compose down
```
