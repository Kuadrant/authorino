# User guide: Token normalization

Broadly, the term token normalization in authentication systems usually implies the exchange of an authentication token, as provided by the user in a given format, and/or its associated identity claims, for another freshly issued token/set of claims, of a given (normalized) structure or format.

The most typical use-case for token normalization envolves accepting tokens issued by multiple trusted sources and of often varied authentication protocols, while ensuring that the eventual different data structures adopted by each of those sources are normalized, thus allowing to simplify policies and authorization checks that depend on those values. In general, however, any modification to the identity claims can be for the purpose of normalization.

This user guide focuses on the aspect of mutation of the identity claims resolved from an authentication token, to a certain data format and/or by extending them, so that required attributes can thereafter be trusted to be present among the claims, in a desired form. For such, Authorino allows to extend resolved identity objects with custom attributes (custom claims) of either static values or with values fetched from the [Authorization JSON](./../architecture.md#the-authorization-json).

For not only normalizing the identity claims for purpose of writing simpler authorization checks and policies, but also getting Authorino to issue a new token in a normalized format, check the [Festival Wristband tokens](./../features.md#festival-wristband-tokens-responsewristband) feature.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#extra-identity-extension-extendedproperties">Identity extension</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc">OpenID Connect (OIDC) JWT/JOSE verification and validation</a></li>
      <li>Authorization → <a href="./../features.md#json-pattern-matching-authorization-rules-authorizationjson">JSON pattern-matching authorization rules</a></li>
    </ul>
  </summary>

  Check out as well the user guides about [Authentication with API keys](./api-key-authentication.md), [OpenID Connect Discovery and authentication with JWTs](./oidc-jwt-authentication.md) and [Simple pattern-matching authorization policies](./user-guides/json-pattern-matching-authorization.md).

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- Auth server / Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq), to extract parts of JSON responses

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-trial
```

Deploy a Keycloak server preloaded with all the realm settings required for this guide:

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

## 1. Install the Authorino Operator

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

## 2. Create the namespace

```sh
kubectl create namespace authorino
```

## 3. Deploy the Talker API

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl -n authorino apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## 4. Deploy Authorino

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
EOF
```

The command above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `namespaced` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 5. Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#1-setup-envoy) page. For a simpler and straighforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl -n authorino apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
```

## 6. Create the `AuthConfig`

This example implements a policy that only users bound to the `admin` role can send `DELETE` requests.

The config trusts access tokens issued by a Keycloak realm as well as API keys labeled specifically to a selected group (`friends`). The roles of the identities handled by Keycloak are managed in Keycloak, as _realm roles_. Particularly, users `john` and `peter` are bound to the `member` role, while user `jane` is bound to roles `member` and `admin`. As for the users authenticating with API key, they are all bound to the `admin` role.

Without normalizing identity claims from these two different sources, the policy would have to handle the differences of data formats with additional ifs-and-elses. Instead, the config here uses the `identity.extendedProperties` option to ensure a custom `roles` (Array) claim is always present in the identity object. In the case of Keycloak ID tokens, the value is extracted from the `realm_access.roles` claim; for API key-resolved objects, the custom claim is set to the static value `["admin"]`.

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
  identity:
  - name: keycloak-kuadrant-realm
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
    extendedProperties:
    - name: roles
      valueFrom:
        authJSON: auth.identity.realm_access.roles
  - name: api-key-friends
    apiKey:
      labelSelectors:
        group: friends
    credentials:
      in: authorization_header
      keySelector: APIKEY
    extendedProperties:
    - name: roles
      value: ["admin"]
  authorization:
  - name: only-admins-can-delete
    json:
      conditions:
      - selector: context.request.http.method
        operator: eq
        value: DELETE
      rules:
      - selector: auth.identity.roles
        operator: incl
        value: admin
EOF
```

## 7. Create an API key

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.3scale.net/managed-by: authorino
    group: friends
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

## 8. Consume the API

### Obtain an access token and consume the API as Jane (admin)

Obtain an access token with the Keycloak server for Jane:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user Jane, whose e-mail has been verified:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r .access_token)
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

Consume the API as Jane:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

### Obtain an access token and consume the API as John (member)

Obtain an access token with the Keycloak server for John:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' | jq -r .access_token)
```

Consume the API as Jane:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 403 Forbidden
```

### Consume the API using the API key to authenticate (admin)

```sh
curl -H "Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-trial
```

Otherwise, delete the namespaces created in step 1 and 2:

```sh
kubectl -n authorino namespace authorino
kubectl -n authorino namespace authorino-operator
```

To uninstall the Authorino and Authorino Operator manifests, run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
