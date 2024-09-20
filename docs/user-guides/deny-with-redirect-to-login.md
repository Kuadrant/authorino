# User guide: Redirecting to a login page

Customize response status code and headers on failed requests to redirect users of a web application protected with Authorino to a login page instead of a `401 Unauthorized`.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Dynamic response → [Custom denial status](../features.md#custom-denial-status-responseunauthenticated-and-responseunauthorized)
  - Identity verification & authentication → [API key](../features.md#api-key-authenticationapikey)
  - Identity verification & authentication → [JWT verification](../features.md#jwt-verification-authenticationjwt)

  Authorino's default response status codes, messages and headers for unauthenticated (`401`) and unauthorized (`403`) requests can be customized with static values and values fetched from the [Authorization JSON](../architecture.md#the-authorization-json).

  Check out as well the user guides about [HTTP "Basic" Authentication (RFC 7235)](http-basic-authentication.md) and [OpenID Connect Discovery and authentication with JWTs](oidc-jwt-authentication.md).

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

<br/>

The next steps walk you through installing Authorino, deploying and configuring a sample web application called **Matrix Quotes** to be protected by the authorization service.

<table>
  <thead>
    <tr>
      <th>Using Kuadrant</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>
        <p>If you are a user of <a href="https://kuadrant.io">Kuadrant</a> and already have your workload cluster configured and sample service application deployed, as well as your Gateway API network resources applied to route traffic to your service, skip straight to step ❺.</p>
        <p>At step ❺, instead of creating an <code>AuthConfig</code> custom resource, create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> one. The schema of the AuthConfig's <code>spec</code> matches the one of the AuthPolicy's, except <code>spec.host</code>, which is not available in the Kuadrant AuthPolicy. Host names in a Kuadrant AuthPolicy are inferred automatically from the Kubernetes network object referred in <code>spec.targetRef</code> and route selectors declared in the policy.</p>
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

## ❷ Deploy Authorino

The following command will request an instance of Authorino as a separate service[^1] that watches for `AuthConfig` resources in the `default` namespace[^2], with TLS disabled[^3].

```sh
kubectl apply -f -<<EOF
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

[^1]: In contrast to a dedicated sidecar of the protected service and other architectures. Check out __Architecture > [Topologies](../architecture.md#topologies)__ for all options.
[^2]: `namespaced` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^3]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.

## ❸ Deploy the Matrix Quotes web application

The **Matrix Quotes** is a static web application that contains quotes from the film _The Matrix_.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/matrix-quotes/matrix-quotes-deploy.yaml
```

## ❹ Setup Envoy

The following bundle from the Authorino examples deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Matrix Quotes webapp behind the reverse-proxy, with external authorization enabled with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/matrix-quotes/envoy-deploy.yaml
```

The command above creates an `Ingress` with host name `matrix-quotes.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8000 to the Envoy service running inside the cluster:

```sh
kubectl port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
```

## ❺ Create an `AuthConfig`

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced:

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
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: matrix-quotes-protection
spec:
  hosts:
  - matrix-quotes.127.0.0.1.nip.io
  authentication:
    "browser-users":
      apiKey:
        selector:
          matchLabels:
            group: users
      credentials:
        cookie:
          name: TOKEN
    "http-basic-auth":
      apiKey:
        selector:
          matchLabels:
            group: users
      credentials:
        authorizationHeader:
          prefix: Basic
  response:
    unauthenticated:
      code: 302
      headers:
        "Location":
          selector: "http://matrix-quotes.127.0.0.1.nip.io:8000/login.html?redirect_to={request.path}"
EOF
```

Check out the docs for information about the common feature [JSON paths](../features.md#common-feature-json-paths-selector) for reading from the [Authorization JSON](../architecture.md#the-authorization-json).

## ❻ Create an API key

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: user-credential-1
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: users
stringData:
  api_key: am9objpw # john:p
type: Opaque
EOF
```

## ❼ Consume the application

On a web browser, navigate to http://matrix-quotes.127.0.0.1.nip.io:8000.

Click on the cards to read quotes from characters of the movie. You should be redirected to login page.

Log in using John's credentials:
- **Username:** john
- **Password:** p

Click again on the cards and check that now you are able to access the inner pages.

You can also consume a protected endpoint of the application using HTTP Basic Authentication:

```sh
curl -u john:p http://matrix-quotes.127.0.0.1.nip.io:8000/neo.html
# HTTP/1.1 200 OK
```

## ❽ (Optional) Modify the `AuthConfig` to authenticate with OIDC

### Setup a Keycloak server

Deploy a Keycloak server preloaded with a realm named `kuadrant`:

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

Resolve local Keycloak domain so it can be accessed from the local host and inside the cluster with the name: (This will be needed to redirect to Keycloak's login page and at the same time validate issued tokens.)

```sh
echo '127.0.0.1 keycloak' >> /etc/hosts
```

Forward local requests to the instance of Keycloak running in the cluster:

```sh
kubectl port-forward deployment/keycloak 8080:8080 2>&1 >/dev/null &
```

Create a client:

```sh
curl -H "Authorization: Bearer $(curl http://keycloak:8080/realms/master/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=admin-cli' -d 'username=admin' -d 'password=p' | jq -r .access_token)" \
     -H 'Content-type: application/json' \
     -d '{ "name": "matrix-quotes", "clientId": "matrix-quotes", "publicClient": true, "redirectUris": ["http://matrix-quotes.127.0.0.1.nip.io:8000/auth*"], "enabled": true }' \
     http://keycloak:8080/admin/realms/kuadrant/clients
```

### Reconfigure the Matrix Quotes app to use Keycloak's login page

```sh
kubectl set env deployment/matrix-quotes KEYCLOAK_REALM=http://keycloak:8080/realms/kuadrant CLIENT_ID=matrix-quotes
```

### Apply the changes to the `AuthConfig`

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: matrix-quotes-protection
spec:
  hosts:
  - matrix-quotes.127.0.0.1.nip.io
  authentication:
    "idp-users":
      jwt:
        issuerUrl: http://keycloak:8080/realms/kuadrant
      credentials:
        cookie:
          name: TOKEN
  response:
    unauthenticated:
      code: 302
      headers:
        "Location":
          selector: "http://keycloak:8080/realms/kuadrant/protocol/openid-connect/auth?client_id=matrix-quotes&redirect_uri=http://matrix-quotes.127.0.0.1.nip.io:8000/auth?redirect_to={request.path}&scope=openid&response_type=code"
EOF
```

### Consume the application again

Refresh the browser window or navigate again to http://matrix-quotes.127.0.0.1.nip.io:8000.

Click on the cards to read quotes from characters of the movie. You should be redirected to login page this time served by the Keycloak server.

Log in as Jane (a user of the Keycloak realm):
- **Username:** jane
- **Password:** p

Click again on the cards and check that now you are able to access the inner pages.

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete secret/user-credential-1
kubectl delete authconfig/matrix-quotes-protection
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/matrix-quotes/matrix-quotes-deploy.yaml
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
