# Welcome to Authorino!

Authorino is an AuthN/AuthZ proxy that implements [Envoy’s external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz)
gRPC protocol. It adds protection to your cloud-native APIs with:
- User authentication (OIDC, user/passwd, mTLS)
- Ad-hoc metadata addition to the authorization payload (user info, resource metadata, web hooks)
- Authorization policy enforcement (built-in and external authorization services, JWT claims, OPA, Keycloak)

**Current stage:** Proof of Concept

## How it works

<!--
  "API consumer" -> Envoy : 1. HTTP request
  Envoy -> Authorino : 2. gRPC
  Authorino -> Authorino : 3. Verify identity
  Authorino -> Authorino : 4. Add metadata
  Authorino -> Authorino : 5. Evaluate policies
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
           │                    │                  │                        │
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
           │                    │                      │ 5. Evaluate policies
           │                    │                  <───┘
           │                    │                  │                        │
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

Authorino is deployed including configuration for steps 3, 4 and 5, for one or more upstream APIs. Then...
1. An _API consumer_ sends a request to the _Envoy_ endpoint, including the `Authorization` and `Host` HTTP headers
2. The Envoy proxy establishes fast gRPC connection with _Authorino_ carrying data of the HTTP request
3. Authorino verifies the identity of the the original requestor, where at least one authentication method/provider should match
4. Authorino integrates external sources to add metadata to the authorization payload, such as user info, attributes of the requested resource and payload-mutating web hooks
5. Authorino dispatches authorization policy evaluation to one or more configured authorization services
6. Authorino and Envoy settle the authorization protocol with either a `200 OK`, `403 Forbidden` or `404 Not found` response
7. If authorized, Envoy redirects to the requested _Upstream_
8. The Upstream serves the requested resource

## Features

Authorino will support at least 3 different authentication methods (i.e., OIDC, user/passwd and mTLS), plus ad-hoc
additions to the authorization payload (e.g., user info, resource metadata, web hooks), and combination of multiple
authorization services (JWT claims, OPA, Keycloak), all driven by configuration. Authorino will also handle caching of
user credentials, permissions, revocations, etc.

| Feature                                      | Stage       |
| -------------------------------------------- | ----------- |
| Multitenancy (multiple upstreams)            | PoC         |
| Identity verification                                      |
| - OpenID Connect (OIDC)                      | PoC         |
| - User/passwd                                | Planned     |
| - mTLS                                       | Planned     |
| Ad-hoc metadata                                            |
| - OIDC user info                             | PoC         |
| - Resource attributes                        | Planned     |
| - Web hooks                                  | In analysis |
| Authorization services                                     |
| - OPA inline Rego policies                   | PoC         |
| - OPA simple pattern matching                | In analysis |
| - Keycloak (UMA-compliant Authorization API) | In analysis |
| - JWT claims                                 | Planned     |
| Caching                                                    |
| - OID config                                 | PoC         |
| - JWKS                                       | PoC         |
| - Authorization policies                     | Planned     |
| - Revoked access tokens                      | Planned     |
| - Repeated requests                          | In analysis |

#### OpenID Connect (OIDC)
Authorino automatically discovers OIDC configurations for the registered issuers and verifies authorization JSON Web
Tokens (JWTs) provided by the API consumers on every request.

Authorino also automatically fetches the JSON Web Key Sets (JWKS) used to verify the JWT, matching the `kid` (easy key
rotation).

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
          │                         │
          │   Well-Known config     │
          │<────────────────────────│
          │                         │
          │     Req OIDC certs      │
          │────────────────────────>│
          │                         │
          │          JWKS           │
          │<────────────────────────│
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

#### OPA
You can model authorization policies in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) and
add them as part of the configuration of your protected APIs. Authorino will keep track of changes to the policies and
automatically register them the OPA server.

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

We are currently working on the features to support use case A and, at the same time, planning for soon having Authorino
configured and deployed with Red Hat 3scale to support use case B. The latter will allow API providers to configure
access control over resources of the API management system in the same fashion they do for their managed APIs.

To use Authorino to protect your APIs with OIDC and OPA, please consider the following requirements and deployment options.

#### Requirements

1. At least one upstream API (i.e., the one API you want to protect)
2. [Envoy](https://www.envoyproxy.io) proxy managing the HTTP connections to the upstream service and with the [External Authorization Filter](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) configured pointing to Authorino (default port: 50051).
3. For OpenID Connect, an authority that can issue JWTs
4. OPA server (default port: 8181)

#### Deploy Authorino on Docker

```
docker run -v './path/to/config.yml:/usr/src/app/config.yml' -p '50051:50051' 3scale/authorino:latest
```

#### Deploy Authorino on a Kubernetes cluster

Please check the [example](examples/openshift), where Authorino is deployed with an OPA sidecar.

To build your proper Authorino config file, please refer to the instructions in the next section. For deployment
to Kubernetes, we recommend creating a `ConfigMap` (example available [here](examples/openshift/configmap.yaml)).
Follow by creating the Authorino `Deployment` and `Service`.

Usually the order of deployment goes as follows:
1. Upstream API(s)
2. Policy Decision service (e.g. OPA) – unless when deployed as an Authorino sidecard, such as in the example provided
3. Authorino
    - `ConfigMap`
    - `Deployment`
    - `Service`
4. Envoy
    - `ConfigMap`
    - `Deployment`
    - `Service`
    - `Ingress` (and [ingress controller](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)) or Openshift `Route`

#### Configuring Authorino

Authorino configuration is one YAML file and a couple of environment variables:

|          |                                                                                         |
| -------- | --------------------------------------------------------------------------------------- |
| `CONFIG` | Path to the Authorino YAML config                                                       |
| `PORT`   | TCP Port that Authorino will listen for gRPC call from the Envoy proxy (default: 50051) |

The structure of the YAML config is something like the following:

```yaml
<upstream-host>:<port>:
  enabled: true
  identity: # -- list of authentication modes and settings
  metadata: # -- list of metadata sources
  authorization: # -- list of authorization services and settings

<other-upstream>:<port>:
  ...
```

#### Inline Rego policies

For the inline Rego policies in your OPA authorization config, the following objects are available in every document:
- `http_request`
- `identity`
- `metadata`
- `resource` (soon)
- `path` (Array)

## Check the examples and try it out

Try the [example](examples) on your Docker environment.

#### Requirements

1. Docker

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

You'll get the following components up and running:

- **Upstream app**
    Just a simple rack application that echos back in a JSON whatever is gets in the request. You can control the response by passing the custom HTTP headers X-Echo-Status and X-Echo-Message (both optional).
- **Envoy proxy**
    Configured w/ the http filters ext_authz and ratelimit.
- **Authorino**
    The external AuthN/AuthZ proxy with [this configuration](examples/config.yml) preloaded.
- **OPA service**
    An actual Policy Decision Point (PDP) configured in the architecture.
- **Keycloak**
    To issue OIDC access tokens.
    Admin console: http://localhost:8080/auth/admin (admin/p)
    Available users:
    - john/p (member)
    - jane/p (admin)

#### 3. Try out with John (member)
```shell
export ACCESS_TOKEN_JOHN=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: upstream:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/pets -v        # 200 OK
curl -H 'Host: upstream:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/pets/stats -v  # 403 Forbidden
```

#### 4. Try out with Jane (admin)
```shell
export ACCESS_TOKEN_JANE=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: upstream:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/pets -v        # 200 OK
curl -H 'Host: upstream:3000' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/pets/stats -v  # 200 OK
```

#### 5. Shut down and clean up
```
docker-compose down
```
