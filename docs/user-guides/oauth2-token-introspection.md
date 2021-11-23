# User guide: OAuth 2.0 token introspection (RFC 7662)

<details>
  <summary>
    <strong>Features:</strong>
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
- [jq](https://stedolan.github.io/jq/)

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-trial
```

Deploy a a12n-server server preloaded with all the realm settings required for this guide:

```sh
kubectl create namespace a12n-server
kubectl -n a12n-server apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/a12n-server/a12n-server-deploy.yaml
```

Forward local requests to the instance of Keycloak running in the cluster:

```sh
kubectl -n a12n-server port-forward deployment/a12n-server 8531:8531 &
```

## 1. Install the Authorino Operator

```sh
git clone https://github.com/kuadrant/authorino-operator && cd authorino-operator
kubectl create namespace authorino-operator && make install deploy
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

The following bundle from the Authorino examples (commands below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#1-setup-envoy) page. For a simpler and straighforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl -n authorino apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/overlays/notls/configmap.yaml
kubectl -n authorino apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/base/envoy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
```

## 6. Create the `AuthConfig`

Create a required secret, used by Authorino to authenticate with a12n-server during the introspection request:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: oauth2-token-introspection-credentials
stringData:
  clientID: talker-api
  clientSecret: V6g-2Eq2ALB1_WHAswzoeZofJ_e86RI4tdjClDDDb4g
type: Opaque
EOF
```

Create the config:

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
  - name: a12n-server
    oauth2:
      tokenIntrospectionUrl: http://a12n-server.a12n-server.svc.cluster.local:8531/introspect
      credentialsRef:
        name: oauth2-token-introspection-credentials
  authorization:
  - name: can-read
    json:
      rules:
        - selector: auth.identity.privileges.talker-api
          operator: incl
          value: read
EOF
```

For every request, Authorino will verify the token remotely with the a12n-server server.

For authorization, only consumers whose `privileges.talker-api` (returned with the introspected token data by a12n-server) includes the `"read"` permission will be granted access.

## 7. Obtain an access token with the a12n-server server

```sh
ACCESS_TOKEN=$(curl -d 'grant_type=client_credentials' -u service-account-1:FO6LgoMKA8TBDDHgSXZ5-iq1wKNwqdDkyeEGIl6gp0s "http://localhost:8531/token" | jq -r .access_token)
```

You can as well obtain an access token from within the cluster, in case your a12n-server is not reachable from the outside:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://a12n-server.a12n-server.svc.cluster.local:8531/token -s -d 'grant_type=client_credentials' -u service-account-1:FO6LgoMKA8TBDDHgSXZ5-iq1wKNwqdDkyeEGIl6gp0s | jq -r .access_token)
```

Verify the issued token is an opaque access token:

```sh
echo $ACCESS_TOKEN
```

## 8. Consume the API

With a valid access token:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

With a revoked access token:

```sh
curl -d "token=$ACCESS_TOKEN" -u service-account-1:FO6LgoMKA8TBDDHgSXZ5-iq1wKNwqdDkyeEGIl6gp0s "http://localhost:8531/revoke" -i
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer realm="a12n-server"
# x-ext-auth-reason: token is not active
```

With missing or invalid access token:

```sh
curl -H "Authorization: Bearer invalid" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer realm="a12n-server"
# x-ext-auth-reason: token is not active
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind only to test this user guide, delete it by running:

```sh
kind delete cluster --name authorino-trial
```

Otherwise, delete the namespaces created in step 1 and 2:

```sh
kubectl -n authorino namespace authorino
kubectl -n authorino namespace authorino-operator
```

To uninstall the Authorino and Authorino Operator manifests, run from the Authorino Operator directory:

```sh
make uninstall
```
