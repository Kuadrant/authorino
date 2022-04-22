# User guide: OAuth 2.0 token introspection (RFC 7662)

Introspect OAuth 2.0 access tokens (e.g. opaque tokens) for online user data and token validation in request-time.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#oauth-20-introspection-identityoauth2">OAuth 2.0 introspection</a></li>
      <li>Authorization → <a href="./../features.md#json-pattern-matching-authorization-rules-authorizationjson">JSON pattern-matching authorization rules</a></li>
    </ul>
  </summary>

  Authorino can perform OAuth 2.0 token introspection ([RFC 7662](https://tools.ietf.org/html/rfc7662)) on the access tokens supplied in the requests to protected APIs. This is particularly useful when using opaque tokens, for remote checking the token validity and resolving the identity object.

  _Important!_ Authorino does **not** implement [OAuth2 grants](https://datatracker.ietf.org/doc/html/rfc6749#section-4) nor [OIDC authentication flows](https://openid.net/specs/openid-connect-core-1_0.html#Authentication). As a common recommendation of good practice, obtaining and refreshing access tokens is for clients to negotiate directly with the auth servers and token issuers. Authorino will only validate those tokens using the parameters provided by the trusted issuer authorities.

  Check out as well the user guides about [OpenID Connect Discovery and authentication with JWTs](./oidc-jwt-authentication.md) and [Simple pattern-matching authorization policies](./user-guides/json-pattern-matching-authorization.md).

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- OAuth 2.0 server that implements the token introspection endpoint ([RFC 7662](https://tools.ietf.org/html/rfc7662)) (e.g. [Keycloak](https://www.keycloak.org) or [a12n-server](https://github.com/curveball/a12n-server))
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

Deploy a a12n-server server preloaded with all the realm settings required for this guide:

```sh
kubectl create namespace a12n-server
kubectl -n a12n-server apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/a12n-server/a12n-server-deploy.yaml
```

Forward local requests to the instance of a12n-server running in the cluster:

```sh
kubectl -n a12n-server port-forward deployment/a12n-server 8531:8531 &
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

Create a couple required secret, used by Authorino to authenticate with Keycloak and a12n-server during the introspection request:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-token-introspection-credentials-keycloak
stringData:
  clientID: talker-api
  clientSecret: 523b92b6-625d-4e1e-a313-77e7a8ae4e88
type: Opaque
EOF
```

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-token-introspection-credentials-a12n-server
stringData:
  clientID: talker-api
  clientSecret: V6g-2Eq2ALB1_WHAswzoeZofJ_e86RI4tdjClDDDb4g
type: Opaque
EOF
```

Create the config:

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
  - name: keycloak
    oauth2:
      tokenIntrospectionUrl: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token/introspect
      tokenTypeHint: requesting_party_token
      credentialsRef:
        name: oauth2-token-introspection-credentials-keycloak
  - name: a12n-server
    oauth2:
      tokenIntrospectionUrl: http://a12n-server.a12n-server.svc.cluster.local:8531/introspect
      credentialsRef:
        name: oauth2-token-introspection-credentials-a12n-server
  authorization:
  - name: can-read
    when:
    - selector: auth.identity.privileges
      operator: neq
      value: ""
    json:
      rules:
      - selector: auth.identity.privileges.talker-api
        operator: incl
        value: read
EOF
```

On every request, Authorino will try to verify the token remotely with the Keycloak server and the a12n-server server.

For authorization, whenever the introspected token data includes a `privileges` property (returned by a12n-server), Authorino will enforce only consumers whose `privileges.talker-api` includes the `"read"` permission are granted access.

Check out the docs for information about the common feature [Conditions](./../features.md#common-feature-conditions-when) about skipping parts of an `AuthConfig` in the auth pipeline based on context.

## 7. Obtain an access token and consume the API

### Obtain an access token with Keycloak and consume the API

Obtain an access token with the Keycloak server for user Jane:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user Jane, whose e-mail has been verified:

```sh
export $(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r '"ACCESS_TOKEN="+.access_token,"REFRESH_TOKEN="+.refresh_token')
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

As user Jane, consume the API:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Revoke the access token and try to consume the API again:

```sh
kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/logout -H "Content-Type: application/x-www-form-urlencoded" -d "refresh_token=$REFRESH_TOKEN" -d 'token_type_hint=requesting_party_token' -u demo:
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer realm="keycloak"
# www-authenticate: Bearer realm="a12n-server"
# x-ext-auth-reason: {"a12n-server":"token is not active","keycloak":"token is not active"}
```

### Obtain an access token with a12n-server and consume the API

Obtain an access token with the a12n-server server for service account `service-account-1`:

```sh
ACCESS_TOKEN=$(curl -d 'grant_type=client_credentials' -u service-account-1:FO6LgoMKA8TBDDHgSXZ5-iq1wKNwqdDkyeEGIl6gp0s "http://localhost:8531/token" | jq -r .access_token)
```

You can as well obtain an access token from within the cluster, in case your a12n-server is not reachable from the outside:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://a12n-server.a12n-server.svc.cluster.local:8531/token -s -d 'grant_type=client_credentials' -u service-account-1:FO6LgoMKA8TBDDHgSXZ5-iq1wKNwqdDkyeEGIl6gp0s | jq -r .access_token)
```

Verify the issued token is an opaque access token in this case:

```sh
echo $ACCESS_TOKEN
```

As `service-account-1`, consumer the API with a valid access token:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Revoke the access token and try to consume the API again:

```sh
curl -d "token=$ACCESS_TOKEN" -u service-account-1:FO6LgoMKA8TBDDHgSXZ5-iq1wKNwqdDkyeEGIl6gp0s "http://localhost:8531/revoke" -i
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer realm="keycloak"
# www-authenticate: Bearer realm="a12n-server"
# x-ext-auth-reason: {"a12n-server":"token is not active","keycloak":"token is not active"}
```

### Consume the API with a missing or invalid access token

```sh
curl -H "Authorization: Bearer invalid" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer realm="keycloak"
# www-authenticate: Bearer realm="a12n-server"
# x-ext-auth-reason: {"a12n-server":"token is not active","keycloak":"token is not active"}
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
