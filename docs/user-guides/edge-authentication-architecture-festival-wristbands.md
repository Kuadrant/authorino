# User guide: Edge Authentication Architecture (EAA)

Edge Authentication Architecture (EAA) is a pattern where more than extracting authentication logics and specifics from the application codebase to a proper authN/authZ layer, this is pushed to the edge of your cloud network, without violating the Zero Trust principle nevertheless.

The very definition of "edge" is subject to discussion, but the underlying idea is that clients (e.g. API clients, IoT devices, etc.) authenticate with a layer that, before moving traffic to inside the network:
- understands the complexity of all the different methods of authentication supported;
- sometimes some token normalization is involved;
- eventually enforces some preliminary authorization policies; and
- possibly filters data bits that are sensitive to privacy concerns (e.g. to comply with local legislation such as GRPD, CCPA, etc)

As a minimum, EAA allows to simplify authentication between applications and microservices inside the network, as well as to reduce authorization to domain-specific rules and policies, rather than having to deal all the complexity to support all types of clients in every node.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Dynamic response → <a href="./../features.md#festival-wristband-tokens-responsesuccessheadersdynamicmetadatawristband">Festival Wristband tokens</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#extra-identity-extension-authenticationdefaults-and-authenticationoverrides">Identity extension</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-authenticationapikey">API key</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#jwt-verification-authenticationjwt">JWT verification</a></li>
    </ul>
  </summary>

  Festival Wristbands are OpenID Connect ID tokens (signed JWTs) issued by Authorino by the end of the Auth Pipeline, for authorized requests. It can be configured to include claims based on static values and values fetched from the [Authorization JSON](./../architecture.md#the-authorization-json).

  Check out as well the user guides about [Token normalization](./token-normalization.md), [Authentication with API keys](./api-key-authentication.md) and [OpenID Connect Discovery and authentication with JWTs](./oidc-jwt-authentication.md).

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- Auth server / Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq/), to extract parts of JSON responses
- [jwt](https://github.com/mike-engel/jwt-cli), to inspect JWTs (optional)

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-tutorial
```

Deploy a Keycloak server preloaded with all the realm settings required for this guide:

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

Forward local requests to the instance of Keycloak running in the cluster:

```sh
kubectl -n keycloak port-forward deployment/keycloak 8080:8080 &
```

## 1. Install the Authorino Operator

```sh
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
```

## 2. Create the namespaces

For simplicity, this examples will set up edge and internal nodes in different namespaces of the same Kubernetes cluster. Those will share a same single cluster-wide Authorino instance. In real-life scenarios, it does not have to be like that.

```sh
kubectl create namespace authorino
kubectl create namespace edge
kubectl create namespace internal
```

## 3. Deploy Authorino

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

The command above will deploy Authorino as a separate service (as opposed to a sidecar of the protected API and other architectures), in `cluster-wide` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#step-request-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 5. Setup the Edge

### Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#step-setup-envoy) page. For a simpler and straightforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl -n edge apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/eaa/envoy-edge-deploy.yaml
```

The bundle also creates an `Ingress` with host name `edge-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 9000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl -n edge port-forward deployment/envoy 9000:9000 &
```

### Create the `AuthConfig`

Create a required secret, used by Authorino to sign the Festival Wristband tokens:

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

```sh
kubectl -n edge apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: edge-auth
spec:
  hosts:
  - edge-authorino.127.0.0.1.nip.io
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
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
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

## 6. Setup the internal workload

### Deploy the Talker API

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl -n internal apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

### Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#step-setup-envoy) page. For a simpler and straightforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl -n internal apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/eaa/envoy-node-deploy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl -n internal port-forward deployment/envoy 8000:8000 &
```

### Create the `AuthConfig`

```sh
kubectl -n internal apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
  authentication:
    "edge-authenticated":
      jwt:
        issuerEndpoint: http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/edge/edge-auth/wristband
EOF
```

## 7. Create an API key

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

## 8. Consume the API

### Using the API key to authenticate

Authenticate at the edge:

```sh
WRISTBAND_TOKEN=$(curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://edge-authorino.127.0.0.1.nip.io:9000/auth -is | tr -d '\r' | sed -En 's/^x-wristband-token: (.*)/\1/p')
```

Consume the API:

```sh
curl -H "Authorization: Bearer $WRISTBAND_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

Try to consume the API with authentication token that is only accepted in the edge:

```sh
curl -H "Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
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
ACCESS_TOKEN=$(kubectl -n edge run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r .access_token)
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

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
#   "iss": "http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant",
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
WRISTBAND_TOKEN=$(curl -H "Authorization: Bearer $ACCESS_TOKEN" http://edge-authorino.127.0.0.1.nip.io:9000/auth -is | tr -d '\r' | sed -En 's/^x-wristband-token: (.*)/\1/p')
```

Consume the API:

```sh
curl -H "Authorization: Bearer $WRISTBAND_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
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
