# User guide: Edge Authentication Architecture (EAA)

Edge Authentication Architecture (EAA) is a pattern where more than extracting authentication logics and specifics from the application codebase to a proper authN/authZ layer, this is pushed to the edge of your cloud network, without violating the Zero Trust principle nevertheless.

The very definition of "edge" is subject to discussion, but the underlying idea is that clients (e.g. API clients, IoT devices, etc.) authenticate with a layer that, before moving traffic to inside the network:
- understands the complexity of all the different methods of authentication supported;
- sometimes some token normalization is involved;
- eventually enforces some preliminary authorization policies; and
- possibly filters data bits that are sensitive to privacy concerns (e.g. to comply with local legislation such as GRPD, CCPA, etc)

As a minimum, EAA allows to simplify authentication between applications and microservices inside the network, as well as to reduce authorization to domain-specific rules and policies, rather than having to deal all the complexity to support all types of clients in every node.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Dynamic response → [Festival Wristband tokens](../features.md#festival-wristband-tokens-responsesuccessheadersdynamicmetadatawristband)
  - Identity verification & authentication → [Identity extension](../features.md#extra-identity-extension-authenticationdefaults-and-authenticationoverrides)
  - Identity verification & authentication → [API key](../features.md#api-key-authenticationapikey)
  - Identity verification & authentication → [JWT verification](../features.md#jwt-verification-authenticationjwt)

  Festival Wristbands are OpenID Connect ID tokens (signed JWTs) issued by Authorino by the end of the Auth Pipeline, for authorized requests. It can be configured to include claims based on static values and values fetched from the [Authorization JSON](../architecture.md#the-authorization-json).

  Check out as well the user guides about [Token normalization](token-normalization.md), [Authentication with API keys](api-key-authentication.md) and [OpenID Connect Discovery and authentication with JWTs](oidc-jwt-authentication.md).

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)
- Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq), to extract parts of JSON responses
- [jwt](https://github.com/mike-engel/jwt-cli), to inspect JWTs (optional)

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

Deploy the identity provider and authentication server by executing the command below. For the examples in this guide, we are going to use a Keycloak server preloaded with all required realm settings.

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

<br/>

The next steps walk you through installing Authorino and configuring 2 environments of an architecture, `edge` and `internal`.

The first environment is a facade for handling the first layer of authentication and exchanging any valid presented authentication token for a Festival Wristband token. In the second, we will deploy a sample service called **Talker API** that the authorization service will ensure to receive only authenticated traffic presented with a valid Festival Wristband.

<table>
  <thead>
    <tr>
      <th>Using Kuadrant</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>
        <p>If you are a user of <a href="https://kuadrant.io">Kuadrant</a> and already have your workload cluster configured and sample service application deployed, as well as your Gateway API network resources applied to route traffic to your service, skip straight to step ❹.</p>
        <p>At steps ❹ and ❺, instead of creating an <code>AuthConfig</code> custom resource, create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> one. The schema of the AuthConfig's <code>spec</code> matches the one of the AuthPolicy's, except <code>spec.host</code>, which is not available in the Kuadrant AuthPolicy. Host names in a Kuadrant AuthPolicy are inferred automatically from the Kubernetes network object referred in <code>spec.targetRef</code> and route selectors declared in the policy.</p>
        <p>For more about using Kuadrant to enforce authorization, check out <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.</p>
      </td>
    </tr>
  </tbody>
</table>

<br/>

## ❶ Install the Authorino Operator (cluster admin required)

The following command will install the [Authorino Operator](http://github.com/kuadrant/authorino-operator) in the Kubernetes cluster. The operator manages instances of the Authorino authorization service.

```sh
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
```

## ❷ Create the namespaces

For simplicity, this examples will set up edge and internal nodes in different namespaces of the same Kubernetes cluster. Those will share a same single cluster-wide Authorino instance. In real-life scenarios, it does not have to be like that.

```sh
kubectl create namespace authorino
kubectl create namespace edge
kubectl create namespace internal
```

## ❸ Deploy Authorino

The following command will request an instance of Authorino as a separate service[^1] that watches for `AuthConfig` resources cluster-wide[^2], with TLS disabled[^3].

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  clusterWide: true
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
EOF
```

[^1]: In contrast to a dedicated sidecar of the protected service and other architectures. Check out __Architecture > [Topologies](../architecture.md#topologies)__ for all options.
[^2]: `cluster-wide` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^3]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.

## ❹ Setup the Edge

### Setup Envoy

The following bundle from the Authorino examples deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up external authorization with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

```sh
kubectl -n edge apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/eaa/envoy-edge-deploy.yaml
```

The command above creates an `Ingress` with host name `edge.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 9000 to the Envoy service running inside the cluster:

```sh
kubectl -n edge port-forward deployment/envoy 9000:9000 2>&1 >/dev/null &
```

### Create the `AuthConfig`

Create a required secret that will be used by Authorino to sign the Festival Wristband tokens:

```sh
kubectl -n edge apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: wristband-signing-key
stringData:
  key.pem: |
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIDHvuf81gVlWGo0hmXGTAnA/HVxGuH8vOc7/8jewcVvqoAoGCCqGSM49
    AwEHoUQDQgAETJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZxJKDysoGwn
    cnUvHIu23SgW+Ee9lxSmZGhO4eTdQeKxMA==
    -----END EC PRIVATE KEY-----
type: Opaque
EOF
```

Create the config:

<table>
  <tbody>
    <tr>
      <td>
        <b><i>Kuadrant users –</i></b>
        Remember to create an <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> instead of an AuthConfig.
        For more, see <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.
      </td>
    </tr>
  </tbody>
</table>

```sh
kubectl -n edge apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: edge-auth
spec:
  hosts:
  - edge.127.0.0.1.nip.io
  authentication:
    "api-clients":
      apiKey:
        selector:
          matchLabels:
            authorino.kuadrant.io/managed-by: authorino
        allNamespaces: true
      credentials:
        authorizationHeader:
          prefix: APIKEY
      overrides:
        "username":
          selector: auth.identity.metadata.annotations.authorino\.kuadrant\.io/username
    "idp-users":
      jwt:
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
      defaults:
        "username":
          selector: auth.identity.preferred_username
  response:
    success:
      dynamicMetadata:
        "wristband":
          wristband:
            issuer: http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/edge/edge-auth/wristband
            customClaims:
              "username":
                selector: auth.identity.username
            tokenDuration: 300
            signingKeyRefs:
            - name: wristband-signing-key
              algorithm: ES256
EOF
```

## ❺ Setup the internal workload

### Deploy the Talker API

The **Talker API** is a simple HTTP service that echoes back in the response whatever it gets in the request. We will use it in this guide as the sample service to be protected by Authorino.

```sh
kubectl -n internal apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

### Setup Envoy

This other bundle from the Authorino examples deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Talker API behind the reverse-proxy, with external authorization enabled with the Authorino instance.

```sh
kubectl -n internal apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/eaa/envoy-node-deploy.yaml
```

The command above creates an `Ingress` with host name `talker-api.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8000 to the Envoy service running inside the cluster:

```sh
kubectl -n internal port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
```

### Create the `AuthConfig`

<table>
  <tbody>
    <tr>
      <td>
        <b><i>Kuadrant users –</i></b>
        Remember to create an <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> instead of an AuthConfig.
        For more, see <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.
      </td>
    </tr>
  </tbody>
</table>

```sh
kubectl -n internal apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api.127.0.0.1.nip.io
  authentication:
    "edge-authenticated":
      jwt:
        issuerUrl: http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/edge/edge-auth/wristband
EOF
```

## ❻ Create an API key

```sh
kubectl -n edge apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.kuadrant.io/managed-by: authorino
  annotations:
    authorino.kuadrant.io/username: alice
    authorino.kuadrant.io/email: alice@host
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

## ❼ Consume the API

### Using the API key to authenticate

Authenticate at the edge:

```sh
WRISTBAND_TOKEN=$(curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://edge.127.0.0.1.nip.io:9000/auth -is | tr -d '\r' | sed -En 's/^x-wristband-token: (.*)/\1/p')
```

Consume the API:

```sh
curl -H "Authorization: Bearer $WRISTBAND_TOKEN" http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

Try to consume the API with authentication token that is only accepted in the edge:

```sh
curl -H "Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer realm="edge-authenticated"
# x-ext-auth-reason: credential not found
```

(Optional) Inspect the wristband token and verify that it only contains restricted info to authenticate and authorize with internal apps.

```sh
jwt decode $WRISTBAND_TOKEN
# [...]
#
# Token claims
# ------------
# {
#   "exp": 1638452051,
#   "iat": 1638451751,
#   "iss": "http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/edge/edge-auth/wristband",
#   "sub": "02cb51ea0e1c9f3c0960197a2518c8eb4f47e1b9222a968ffc8d4c8e783e4d19",
#   "username": "alice"
# }
```

### Authenticating with the Keycloak server

Obtain an access token with the Keycloak server for Jane:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user Jane, whose e-mail has been verified:

```sh
ACCESS_TOKEN=$(kubectl -n edge run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' -d 'scope=openid' | jq -r .access_token)
```

If your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

(Optional) Inspect the access token issue by Keycloak and verify and how it contains more details about the identity than required to authenticate and authorize with internal apps.

```sh
jwt decode $ACCESS_TOKEN
# [...]
#
# Token claims
# ------------
# { [...]
#   "email": "jane@kuadrant.io",
#   "email_verified": true,
#   "exp": 1638452220,
#   "family_name": "Smith",
#   "given_name": "Jane",
#   "iat": 1638451920,
#   "iss": "http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant",
#   "jti": "699f6e49-dea4-4f29-ae2a-929a3a18c94b",
#   "name": "Jane Smith",
#   "preferred_username": "jane",
#   "realm_access": {
#     "roles": [
#       "offline_access",
#       "member",
#       "admin",
#       "uma_authorization"
#     ]
#   },
# [...]
```

As Jane, obtain a limited wristband token at the edge:

```sh
WRISTBAND_TOKEN=$(curl -H "Authorization: Bearer $ACCESS_TOKEN" http://edge.127.0.0.1.nip.io:9000/auth -is | tr -d '\r' | sed -En 's/^x-wristband-token: (.*)/\1/p')
```

Consume the API:

```sh
curl -H "Authorization: Bearer $WRISTBAND_TOKEN" http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete namespace edge
kubectl delete namespace internal
kubectl delete namespace authorino
kubectl delete namespace keycloak
```

To uninstall the Authorino and Authorino Operator manifests, run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
