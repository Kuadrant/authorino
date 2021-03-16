# Welcome to Authorino!

Authorino is a Cloud Native AuthN/AuthZ broker that implements [Envoy’s external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) gRPC protocol.

It adds protection to your APIs including:
- User authentication (OIDC, mTLS, HMAC, API key)
- Ad-hoc metadata addition to the authorization payload (user info, resource metadata, generic HTTP GET)
- Authorization policy enforcement (built-in and external authorization services, JWT claims, OPA, Keycloak)

Authorino complies with the [3scale Ostia architecture](https://github.com/3scale-labs/ostia).

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
4. **Ad-hoc authorization metadata step** - Authorino integrates external sources to add metadata to the authorization payload, such as user info, attributes of the requested resource and external HTTP GET responses
5. **Policy enforcement step** - Authorino dispatches authorization policy evaluation to one or more configured Policy Decision Points (PDP)
6. Authorino and Envoy settle the authorization protocol with either a `200 OK`, `403 Forbidden` or `404 Not found` response (_Tip:_ with extra details available in the `x-ext-auth-reason` header if NOK)
7. If authorized, Envoy redirects to the requested _Upstream_
8. The Upstream serves the requested resource

The three Authorino's core steps are depicted in the diagram, respectively, as 3, 4 and 5 in the overall flow. These steps rely on well-established industry standards and protocols, such as [OpenID Connect (OIDC)](https://openid.net/connect/), [User-Managed Access (UMA)](https://docs.kantarainitiative.org/uma/rec-uma-core.html), [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) and [mutual Transport Layer Security (mTLS)](https://www.rfc-editor.org/rfc/rfc8705.html), and enable API developers to add API security through configuration by mixing and combining settings to external services that implement such standards. Authorino enforces authentication and authorization to the API requests based on that single file configuration.

_Identity verification_ can be, for example, verifying a provided JSON Web Token (JWT) previously issued by an OIDC-compliant authentication server and provided in the `Authorization` header of the HTTP request. Authorino will auto-discover the OIDC configuration from the settings, verify the token signature and validity in time.

_Ad-hoc authorization metadata_ can be the fetching of OIDC user info (based on the same configuration used for the identity before) and/or about fecthing resource data from a UMA-compliant server that knows about the resources.

_Policy enforcement_ is where Authorino connects to one or more authorization policy evaluation services (or Policy Decision Points (PDP)) that will ultimately decide on whether the HTTP request should be authorized or not, given the known gathered information about the identity, the origin of the request, the requested resource and, of course, the configured policies.

_Identity verification_ and _Ad-hoc authorization metadata_ steps add info for the _Policy enforcement_, meaning API developers can write authorization policies trusting on information available about the requestor's identity (a decoded JWT, for example) and on the metadata added ad-hoc to the authorization payload (e.g. specific user info or data about the requested resource). Of course, if Authorino fails to verify the user's identity in the _Identity verification_ step, the request is rejected without further development of the other two steps.

## Features

Please check the [open issues](https://github.com/3scale-labs/authorino/issues) for a full list of features and most up-to-date statuses. Here's a summary of Authorino's main highlight features and corresponding stages of development:

<table>
  <thead>
    <tr>
      <th colspan="2">Feature</th>
      <th>Stage</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="6">Identity verification</td>
      <td>OpenID Connect (OIDC)</td>
      <td>Available</td>
    </tr>
    <tr>
      <td>API key</td>
      <td>WIP (<a href="https://github.com/3scale-labs/authorino/issues/7">#7</a>)</td>
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
      <td>In analysis</td>
    </tr>
    <tr>
      <td>OpenShift OAuth (built-in auth server)</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="3">Ad-hoc authorization metadata</td>
      <td>OIDC user info</td>
      <td>Available</td>
    </tr>
    <tr>
      <td>UMA-protected resource attributes</td>
      <td>Available</td>
    </tr>
    <tr>
      <td>Generic HTTP GET</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/10">#10</a>)</td>
    </tr>
    <tr>
      <td rowspan="3">Policy enforcement</td>
      <td>OPA inline Rego policies</td>
      <td>Available</td>
    </tr>
    <tr>
      <td>Pattern matching rules (e.g. JWT claims)</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/11">#11</a>)</td>
    </tr>
    <tr>
      <td>Keycloak (UMA-compliant Authorization API)</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="6">Caching</td>
      <td>OIDC and UMA configs</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/2">#2</a>)</td>
    </tr>
    <tr>
      <td>JSON Web Ket Sets (JWKS)</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/2">#2</a>)</td>
    </tr>
    <tr>
      <td>Revoked access tokens</td>
      <td>Planned  (<a href="https://github.com/3scale-labs/authorino/issues/19">#19</a>)</td>
    </tr>
    <tr>
      <td>Resource data</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/21">#21</a>)</td>
    </tr>
    <tr>
      <td>Authorization policies</td>
      <td>Available</td>
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
      <td>Available</td>
    </tr>
    <tr>
      <td colspan="2">HTTP External Authorization</td>
      <td>Planned (<a href="https://github.com/3scale-labs/authorino/issues/6">#6</a>)</td>
    </tr>
    <tr>
      <td colspan="2">External policy registry</td>
      <td>In analysis</td>
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

You can model authorization policies in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) and add them as part of the configuration of your protected APIs. Authorino will keep track of changes to the policies and automatically register them to the built-in OPA module.

<!--
  Authorino -> "Built-in OPA" : Register policy
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
                │         OK/NOK         │
                │<───────────────────────│
           ┌────┴────┐            ┌──────┴─────┐
           │Authorino│            │Built-in OPA│
           └─────────┘            └────────────┘
```

## Usage

Authorino is a Cloud Native application, so you will need a [Kubernetes](https://kubernetes.io) cluster. You may also need typical tools to work with Kubernetes such as [kubectl](https://kubernetes.io/docs/reference/kubectl/overview) and [Kustomize](https://kustomize.io).

Assuming you have the cluster up and running, and hold proper permissions to be able to do things such as create [Custom Resource Definitions (CRDs)](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources) in the cluster, follow the steps below to prepare the environment and add protection to your upstream APIs with Authorino:

### Preparation

1. Create a namespace.
2. Deploy [Envoy](https://www.envoyproxy.io) proxy. Ultimately, Envoy virtual hosts will be associated to the upstream APIs you want to protect, and the [External Authorization Filter](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) pointing to Authorino. Check [this example](examples/envoy.yaml) if you need to.
3. For OpenID Connect, make sure you have access to an identity provider (IdP) and an authority that can issue ID tokens (JWTs). You may want to check out [Keycloak](https://www.keycloak.org) which can solve both and connect to external identity sources and user federation like LDAP.
4. For UMA-protected resource data, you will need a UMA-compliant server running as well. This can be an implementation of the UMA protocol by each upstream API itself or (more tipically) an external server that knows about the resources. Again, Keycloak can be a good fit here as well. Just keep in mind that, whatever resource server you choose, changing-state actions commanded in the upstream APIs or other parties will have to be reflected in the resource server. Authorino will not do that for you. Read more about it [here](#user-managed-access-uma).
5. Create the Authorino CRDs and deploy
    ```
    git clone git@github.com:3scale-labs/authorino.git && cd authorino
    kustomize build config/default | kubectl -n "${AUTHORINO_NAMESPACE}" apply -f -
    ```

Authorino has really only one setting option that can be changed when deploying. The `PORT` environment variable defines the TCP port that Authorino will listen to for the gRPC calls sent by the Envoy proxy. It defaults to port 50051. In case you want to change that, make sure to do the proper adjusments in steps 2 and 5 above.

### Add protection to a upstream API
1. Have your upstream API running. Typically, upstream APIs are deployed to the same cluster and namespace where you have Envoy and Authorino running but not necessarily.
2. Make sure the Envoy config includes a virtual host to the upstream API. You may need to rollout the `envoy` deployment for the changes to take effect.
3. Create an `Ingress` resource exposing the `envoy` service on a host that resolves to the Kubernetes cluster and identifies your API for external users.
4. Write an Authorino `Service` Custom Resource (CR) specifying the auth config to proctect your upstream API. The scheme for the CR is described in [The Authorino Service CR](#the-authorino-service-custom-resource) and you may also want to check [this](examples/echo-api-protection.yaml) more concrete example.
5. Apply the CR with `kubectl -n "${AUTHORINO_NAMESPACE}" apply -f path/to/authorino/auth-config-cr.yaml`

### The Authorino Service Custom Resource

An Authorino `Service` Custom Resource specifies the authN/authZ configuration for a given upstream API. It has the following general structure:

```yaml
apiVersion: config.authorino.3scale.net/v1beta1
kind: Service
metadata:
  name: my-upstream-api
spec:
  # List of hostnames to match the upstream API → Authorino gets the host from the Envoy input and looks up for the corresponding config in its cache
  host: []

  # List of identity sources → Authorino ensures the requestor's credentials (i.e. an access token, a TLS client certificate, etc) are verified with at least one of the sources from this list, implementing the corresponding protocol (e.g. `oidc`, `mtls`, `hmac`)
  identity: []

  # List of sources of additional metadata for the authorization step (e.g. OIDC `userinfo`, `uma`-protected resource attributes) → Authorino fetches the additional metadata according the each protocol and passes it along with the request info and identity info to the Policy Decision Points (PDPs)/authorization services
  metadata: []

  # List of Policy Decision Points (PDPs)/authorization services and corresponding settings (e.g. `opa`, `jwt`)
  authorization: []
```

A more concrete example can be found [here](examples/echo-api-protection.yaml).

#### Inline Rego policies

For inline Rego policies (with the `opa` authorization type), the following objects are available in every document and can be used in the body of any user-defined policy:
- `http_request`: attributes of the HTTP request (e.g., host, path, headers, etc) as passed by Envoy to Authorino
- `identity`: whatever is resolved from the "identity" section of Authorino config, e.g. a decoded JWT of an OIDC authentication
- `metadata`: whatever is resolved from the "metadata" section of Authorino config, e.g. OIDC user info, resource data fetched from a UMA-compliant server
- `path` (Array): just an array of each segment of `http_request.path` to ease writing of rules with comparisson expressions using the requested path.

## Try it out with the example

The only requirements to try out the example are [Golang](https://golang.org) and a [Docker](https://docker.com) daemon running. The development/testing environment consists of a Kubernetes server with the following components:

- **Echo API**<br/>
    Just a simple rack application that echoes back in a JSON whatever is gets in the request. You can control the response by passing the custom HTTP headers X-Echo-Status and X-Echo-Message (both optional).
- **Envoy proxy**<br/>
    Configured w/ the ext_authz http filter.
- **Authorino**<br/>
    The AuthN/AuthZ broker that will look for all Authorino `Service` CRs in the Kubernetes server
- **Keycloak**<br/>
    To issue OIDC access tokens and to provide ad-hoc resource data for the authorization payload.<br/>
    - Admin console: http://localhost:8080/auth/admin (admin/p)
    - Preloaded realm: **ostia**
    - Preloaded clients:
      - **demo**: to which API consumers delegate access and therefore the one which access tokens are issued to
      - **authorino**: used by Authorino to fetch additional user info with `client_credentials` grant type
      - **echo-api**: used by Authorino to fetch UMA-protected resource data associated with the Echo API
    - Preloaded resources:
      - `/hello`
      - `/greetings/1` (owned by user jonh)
      - `/greetings/2` (owned by user jonh)
      - `/bye`
    - Realm roles:
      - member (default to all users)
      - admin
    - Preloaded users:
      - john/p (member)
      - jane/p (admin)

> In case you are interested in using [dex](https://dexidp.io) identity service, check also [this](examples/dex) other example.

#### 1. Clone the repo

```shell
git clone git@github.com:3scale-labs/authorino.git
```

#### 2. Launch the local Kubernetes environment

```shell
cd authorino
make local-setup
```

In the process of setting up your local environment, Authorino's `Makefile` may try to install the following required tools in case they are not already available in your system:
- [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- [Kustomize](https://kustomize.io)

Once the setup finishes and all deployments are ready, expose the Envoy and Keycloak services to the local host by running:

```shell
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
kubectl -n authorino port-forward deployment/keycloak 8080:8080 &
```

Create the secrets that required in the example config:

```shell
kubectl -n authorino create secret generic userinfosecret \
        --from-literal=clientID=authorino \
        --from-literal=clientSecret='2e5246f2-f4ef-4d55-8225-36e725071dee'

kubectl -n authorino create secret generic umacredentialssecret \
        --from-literal=clientID=echo-api \
        --from-literal=clientSecret='523b92b6-625d-4e1e-a313-77e7a8ae4e88'
```

Finally, deploy Authorino auth config with:
```shell
kubectl -n authorino apply -f ./examples/echo-api-protection.yaml
```

#### 3. Try out with John (member)

John is a member user of the `ostia` realm in Keycloak. He owns the resources hosted at `/greetings/1` and `/greetings/2` and has no access to `/bye`.

```shell
export ACCESS_TOKEN_JOHN=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/hello -v        # 200 OK
curl -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/greetings/1 -v  # 200 OK
curl -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/bye -v          # 403 Forbidden
```

#### 4. Try out with Jane (admin)

Jane is an admin user of the `ostia` realm in Keycloak. She does not own any resource and has access to `/bye`.

```shell
export ACCESS_TOKEN_JANE=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/hello -v        # 200 OK
curl -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/greetings/1 -v  # 403 Forbidden
curl -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/bye -v          # 200 OK
```

#### 5. Shut down and clean up
```
kind delete clusters authorino-integration
```


## Terminology
You can find definitions for terms used in this document and others in the [Terminology](docs/terminology.md) document

## Contributing

- Check the list of issues in GitHub
- Make sure you have installed
    - [Docker](https://docker.com)
    - [Golang](https://golang.org)
    - [Operator SDK](https://sdk.operatorframework.io/)
- Fork the repo
- Download dependencies
  `make vendor`
- Start your local changes
- Push a PR
