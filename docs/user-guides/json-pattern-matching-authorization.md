# User guide: Simple pattern-matching authorization policies

Write simple authorization rules based on JSON patterns matched against Authorino's Authorization JSON; check contextual information of the request, validate JWT claims, cross metadata fetched from external sources, etc.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Authorization → <a href="./../features.md#json-pattern-matching-authorization-rules-authorizationjson">JSON pattern-matching authorization rules</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc">OpenID Connect (OIDC) JWT/JOSE verification and validation</a></li>
    </ul>
  </summary>

  Authorino provides a built-in authorization module to check simple pattern-matching rules against the [Authorization JSON](./../architecture.md#the-authorization-json). This is an alternative to [OPA](./../features.md#open-policy-agent-opa-rego-policies-authorizationopa) when all you want is to check for some simple rules, without complex logics, such as match the value of a JWT claim.

  Check out as well the user guide about [OpenID Connect Discovery and authentication with JWTs](./oidc-jwt-authentication.md).

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

Forward local requests to the instance of Keycloak running in the cluster:

```sh
kubectl -n keycloak port-forward deployment/keycloak 8080:8080 &
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

The `email-verified-only` authorization policy ensures that users consuming the API from a given network (IP range 192.168.1/24) must have their emails verified.

The `email_verified` claim is a property of the identity added to the JWT by the OpenID Connect issuer.

The implementation relies on the [`X-Forwarded-For`](https://datatracker.ietf.org/doc/html/rfc7239) HTTP header to read the client's IP address.

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
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
  authorization:
  - name: email-verified-only
    conditions:
    - selector: "context.request.http.headers.x-forwarded-for.@extract:{\"sep\": \",\"}"
      operator: matches
      value: 192\\.168\\.1\\.\\d+
    json:
      rules:
      - selector: auth.identity.email_verified
        operator: eq
        value: "true"
EOF
```

Check out the docs for information about semantics and operators supported by the [JSON pattern-matching authorization](./../features.md#json-pattern-matching-authorization-rules-authorizationjson) feature, as well the common feature [JSON paths](./../features.md#common-feature-json-paths-valuefromauthjson) for reading from the [Authorization JSON](./../architecture.md#the-authorization-json), including the description of the string modifier `@extract` used above. Check out as well the common feature [Conditions](./../architecture.md#common-feature-conditions) about skipping parts of an `AuthConfig` in the auth pipeline based on context..

## 7. Obtain an access token and consume the API

### Obtain an access token and consume the API as Jane (email verified)

Obtain an access token with the Keycloak server for Jane:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user Jane, whose e-mail has been verified:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r .access_token)
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

As Jane, consume the API outside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 123.45.6.78' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As Jane, consume the API inside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 192.168.1.10' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

### Obtain an access token and consume the API as Peter (email NOT verified)

Obtain an access token with the Keycloak server for Peter:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=peter' -d 'password=p' | jq -r .access_token)
```

As Peter, consume the API outside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 123.45.6.78' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As Peter, consume the API inside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 192.168.1.10' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Unauthorized
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
