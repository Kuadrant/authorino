# Authorino

Cloud-native AuthN/AuthZ enforcer to protect APIs.

- **User authentication/identity verification**<br/>
  API key, OAuth2, OIDC, mTLS, HMAC, K8s-auth
- **Ad-hoc authorization metadata**<br/>
  OIDC UserInfo, UMA-protected resource data, HTTP GET-by-POST
- **Authorization policy enforcement**<br/>
  OPA/Rego policies, JSON/JWT pattern matching policies

Authorino enables hybrid API security layer, with usually no code changes required, according to your own desired combination of authentication standards and authorization policies.

Authorino implements [Envoy](https://www.envoyproxy.io) proxy's [external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) gRPC protocol and complies with Red Hat 3scale [Kuadrant](https://github.com/kuadrant) architecture.

## How it works

<!--
  "API consumer" -> Envoy : 1. HTTP request
  Envoy -> Authorino : 2. gRPC
  Authorino -> Authorino : 3. Verify identity
  Authorino -> Authorino : 4. Add metadata
  Authorino -> Authorino : 5. Enforce policies
  Authorino -> Envoy : 6. OK
  Envoy -> "Upstream API" : 7. HTTP request
  "Upstream API" -> "API consumer" : 8. HTTP response
-->
```
     ┌────────────┐          ┌─────┐          ┌─────────┐               ┌────────────┐
     │API consumer│          │Envoy│          │Authorino│               │Upstream API│
     └─────┬──────┘          └──┬──┘          └────┬────┘               └──────┬─────┘
           │  1. HTTP request   │                  │                           │
           │ ──────────────────>│                  │                           │
           │                    │     2. gRPC      │                           │
           │                    │─────────────────>│                           │
           │                    │                  │                           │
           │                    │                  ────┐                       │
           │                    │                      │ 3. Verify identity    │
           │                    │                  <───┘                       │
           │                    │                  │                           │
           │                    │                  ────┐                       │
           │                    │                      │ 4. Add metadata       │
           │                    │                  <───┘                       │
           │                    │                  │                           │
           │                    │                  ────┐                       │
           │                    │                      │ 5. Enforce policies   │
           │                    │                  <───┘                       │
           │                    │      6. OK       │                           │
           │                    │<─────────────────│                           │
           │                    │                  │                           │
           │                    │              7. HTTP request                 │
           │                    │─────────────────────────────────────────────>│
           │                    │                  │                           │
           │                    │   8. HTTP response                           │
           │ <─────────────────────────────────────────────────────────────────│
     ┌─────┴──────┐          ┌──┴──┐          ┌────┴────┐               ┌──────┴─────┐
     │API consumer│          │Envoy│          │Authorino│               │Upstream API│
     └────────────┘          └─────┘          └─────────┘               └────────────┘
```

1. An application client (_API consumer_) obtains credentials to consume resources of the _Upstream API_, and sends a request to the _Envoy_ exposed endpoint
2. The Envoy proxy establishes fast gRPC connection with _Authorino_ carrying data of the HTTP request (context info)
3. **Identity verification phase** - Authorino verifies the identity of the the consumer, where at least one authentication method/identity provider must answer
4. **Ad-hoc authorization metadata phase** - Authorino integrates external sources of additional metadata
5. **Policy enforcement phase** - Authorino takes as input a JSON composed of context information, resolved identity and fetched additional metadata from previous phases, and triggers the evaluation of configured authorization policies
6. Authorino and Envoy settle the authorization protocol with either a `200 OK`, `403 Forbidden` or `404 Not found` response (plus some extra details available in the `x-ext-auth-reason` header if NOK)
7. If authorized, Envoy redirects to the requested _Upstream API_
8. The _Upstream API_ serves the requested resource to the consumer

The 3 _core phases_ of Authorino _auth pipeline_ (depicted in the diagram as steps 3, 4 and 5) rely on well-established industry standards and protocols, such as [OpenID Connect (OIDC)](https://openid.net/connect/), [User-Managed Access (UMA)](https://docs.kantarainitiative.org/uma/rec-uma-core.html), [Open Policy Agent (OPA)](https://www.openpolicyagent.org/), [mutual Transport Layer Security (mTLS)](https://www.rfc-editor.org/rfc/rfc8705.html), among others, to enable API security while allowing API developers to pick and combine protocols and settings into one hybrid cloud-native configuration.

## Architecture

### Protecting upstream APIs with Authorino and Envoy

Typically, upstream APIs are deployed to the same Kubernetes cluster and namespace where Envoy and Authorino is running (although not necessarily). Whatever is the case, the Envoy proxy must be serving the upstream API (see Envoy's [HTTP route components](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto) and virtual hosts).

An `Ingress` resource exposing Envoy service on a host name that must resolves to the Kubernetes cluster and identifies the API for external users. This host name is important as well for Authorino as it goes in the Authorino `Service` custom resource that declares the protection to the API.

You must then be ready to write and apply the custom resource that describes the desired state of the protection for the API.

There is no need to redeploy neither Authorino nor Envoy after applying a protection config. Authorino controller will automatically detect any changes relative to `config.authorino.3scale.net`/`Service` resources and reconcile them inside the running instances.

### The Authorino `Service` custom resource

Please check out the [spec](config/crd/bases/config.authorino.3scale.net_services.yaml) of the Authorino `Service` custom resource for the details.

A list of more concrete examples can be found [here](examples).

### The "auth pipeline" (aka Authorino's 3 core "phases")

In each request to the protected API, Authorino triggers the so-called "auth pipeline", a set of configured *evaluators* organized in up to 3 "phases" – namely (i) Identity phase, (ii) Metadata phase and (iii) Authorization phase. The evaluators in each phase are concurrent to each other, while the 3 phases are sequential.

- **(i) Identity phase:** at least one source of identity must resolve the supplied credential in the request into a valid identity or Authorino will otherwise reject the request as unauthenticated.
- **(ii) Metadata phase:** completely optional fetching of additional data from external sources, to add up to context information and identity information, and used in authorization policies (phase iii).
- **(iii) Authorization phase:** all policies must either explicitly skipped or evaluate to a positive result ("authorized"), or Authorino will otherwise reject the request as unauthorized.

Along the auth pipeline, Authorino builds the *authorization payload*, a JSON content composed of *context* information about the request, as provided by the proxy to Authorino, plus *auth* objects resolved and collected along of phases (i) and (ii). In each phase, the authorization JSON can be accessed by the evaluators, leading to phase (iii) counting with a payload (input) that looks like the following:

```jsonc
// The authorization JSON combined along Authorino's auth pipeline for each request
{
  "context": { // the input from the proxy
    "origin": {…},
    "request": {
      "http": {
        "method": "…",
        "headers": {…},
        "path": "/…",
        "host": "…",
        …
      }
    }
  },
  "auth": {
    "identity": {
      // the identity resolved, from the supplied credentials, by one of the evaluators of phase (i)
    },
    "metadata": {
      // each metadata object/collection resolved by the evaluators of phase (ii)
    }
  }
}
```

The authorization policies evaluated in phase (iii) can use any info from the authorization JSON to define rules.

### List of features

<table>
  <thead>
    <tr>
      <th colspan="2">Feature</th>
      <th>Stage</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="7">Identity verification</td>
      <td>API key</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>mTLS</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/8">#8</a>)</td>
    </tr>
    <tr>
      <td>HMAC</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/9">#9</a>)</td>
    </tr>
    <tr>
      <td>OAuth2</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/82">#62</a>)</td>
    </tr>
    <tr>
      <td>OpenID Connect (OIDC)</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Kubernetes auth (SA token/TokenReview API)</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OpenShift OAuth (user-echo endpoint)</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="3">Ad-hoc authorization metadata</td>
      <td>OIDC user info</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>UMA-protected resource attributes</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>HTTP GET-by-POST</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/10">#10</a>)</td>
    </tr>
    <tr>
      <td rowspan="4">Policy enforcement</td>
      <td>JSON pattern matching (e.g. JWT claims)</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OPA Rego policies</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Keycloak (UMA-compliant Authorization API)</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td>HTTP external authorization service</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="6">Caching</td>
      <td>OIDC and UMA configs</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>JSON Web Keys (JWKs) and JSON Web Ket Sets (JWKS)</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Revoked access tokens</td>
      <td>In analysis (<a href="https://github.com/3scale-labs/authorino/issues/19">#19</a>)</td>
    </tr>
    <tr>
      <td>Resource data</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/21">#21</a>)</td>
    </tr>
    <tr>
      <td>Compiled Rego policies</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Repeated requests</td>
      <td>In analysis (<a href="https://github.com/3scale-labs/authorino/issues/20">#20</a>)</td>
    </tr>
    <tr>
      <td colspan="2">Mutate request with auth data</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/22">#22</a>)</td>
    </tr>
    <tr>
      <td colspan="2">Token normalization (Edge Auth)</td>
      <td>In analysis (<a href="https://github.com/3scale-labs/authorino/issues/24">#24</a>)</td>
    </tr>
    <tr>
      <td colspan="2">Multitenancy (multiple upstreams and hosts)</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td colspan="2">External policy registry</td>
      <td>In analysis</td>
    </tr>
  </tbody>
</table>

#### OpenID Connect (OIDC)

Authorino automatically discovers OIDC configurations for the registered issuers and verifies JSON Web Tokens (JWTs) supplied by the API consumers on each request.

Authorino also fetches the JSON Web Key Sets (JWKS) used to verify the JWTs, matching the `kid` stated in the JWT header (i.e., support to easy key rotation).

In general, OIDC confgurations are essentially used in the identity verification phase and possibly as well in the ad-hoc authorization metadata phase of Authorino. The decoded JWTs (and fetched user info) are passed in the authorization payload to phase (iii), i.e., authorization policy enforcement.

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
                      ·                         ·
Reconciliation-time:  │     OIDC discovery      │
                      │────────────────────────>│
                      │    Well-Known config    │
             (cache)  │<────────────────────────│
                      │                         │
                      │     Req OIDC certs      │
                      │────────────────────────>│
                      │          JWKS           │
             (cache)  │<────────────────────────│
                      ·                         ·
Request-time:         │                         │
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

This enables the implementation of resource-level Attribute-Based Access Control (ABAC) policies. Attributes of the resource fetched in a UMA flow can be, e.g., the owner of the resource, or any business-level attributes stored in the UMA-compliant server.

A UMA-compliant server is an external authorization server (e.g., Keycloak) where the protected resources are registered. It can be as well the upstream API itself, as long as it implements the UMA protocol, with initial authentication by `client_credentials` grant to exchange for a Protected API Token (PAT).

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
                      ·                           ·
Reconciliation-time:  │       UMA Discovery       │
                      │───────────────────────────>
                      │     Well-Known config     │
             (cache)  │<───────────────────────────
                      │                           │
                      ·                           ·
Request-time:         │        Request PAT        │
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

The resources data is added as metadata of the authorization payload and passed as input for the configured authorization policies. All resources returned by the UMA-compliant server in the query by URI are passed along. They are available in the PDPs (authorization payload) as `input.auth.metadata.custom-name => Array`. (See [The "auth pipeline"](#the-auth-pipeline-aka-authorinos-3-core-phases) for details.)

#### Open Policy Agent (OPA)

You can model authorization policies in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) and add them as part of the protection of your APIs. Authorino reconciliation cycle keeps track of any changes in the custom resources affecting the written policies and automatically recompiles them with built-in OPA module, and cache them for fast evaluation during request-time.

<!--
  Authorino -> "Built-in OPA" : Register policy
  "Built-in OPA" -> "Built-in OPA" : Compile policy
  "Built-in OPA" -> Authorino
  Authorino -> "Built-in OPA" : Get document with input
  "Built-in OPA" -> "Built-in OPA" : Evaluate policy
  "Built-in OPA" -> Authorino : OK/NOK
-->
```
                 ┌─────────┐            ┌────────────┐
                 │Authorino│            │Built-in OPA│
                 └────┬────┘            └──────┬─────┘
                      ·                        ·
Reconciliation-time:  │    Register policy     │
                      │───────────────────────>│
                      │                        │
                      │                        ────┐
                      │                            │ Compile policy
                      │                        <───┘
              (cache) │<───────────────────────│
                      │                        │
                      ·                        ·
Request-time:         │Get document with input │
                      │───────────────────────>│
                      │                        │
                      │                        ────┐
                      │                            │ Evaluate policy
                      │                        <───┘
                      │         OK/NOK         │
                      │<───────────────────────│
                 ┌────┴────┐            ┌──────┴─────┐
                 │Authorino│            │Built-in OPA│
                 └─────────┘            └────────────┘
```

## Usage

1. [Deploy](docs/deploy.md) Authorino to the Kubernetes server
2. Have your upstream API [ready](#protecting-upstream-apis-with-authorino-and-envoy) to be protected
3. [Write](#the-authorino-service-custom-resource) and apply a `config.authorino.3scale.net`/`Service` custom resource declaring the desired state of the protection of your API

## Sample use cases

The [Examples](examples) page lists several use cases and demonstrates how to implement those as Authorino custom resources.

## Terminology

You can find definitions for terms used in this document and others in the [Terminology](docs/terminology.md) document.

## Contributing

If you are interested in contributing to Authorino, please refer to instructions available [here](docs/contributing.md). You may as weel check our [Code of Conduct](docs/code_of_conduct.md).
