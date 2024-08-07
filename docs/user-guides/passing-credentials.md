# User guide: Passing credentials (`Authorization` header, cookie headers and others)

Customize where credentials are supplied in the request by each trusted source of identity.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Identity verification & authentication →[Auth credentials](../features.md#extra-auth-credentials-authenticationcredentials)
  - Identity verification & authentication →[API key](../features.md#api-key-authenticationapikey)

  Authentication tokens can be supplied in the `Authorization` header, in a custom header, cookie or query string parameter.

  Check out as well the user guide about [Authentication with API keys](api-key-authentication.md).

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

<br/>

The next steps walk you through installing Authorino, deploying and configuring a sample service called **Talker API** to be protected by the authorization service.

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

## ❸ Deploy the Talker API

The **Talker API** is a simple HTTP service that echoes back in the response whatever it gets in the request. We will use it in this guide as the sample service to be protected by Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## ❹ Setup Envoy

The following bundle from the Authorino examples deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Talker API behind the reverse-proxy, with external authorization enabled with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The command above creates an `Ingress` with host name `talker-api.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8000 to the Envoy service running inside the cluster:

```sh
kubectl port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
```

## ❺ Create an `AuthConfig`

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced.

In this example, `member` users can authenticate supplying the API key in any of 4 different ways:
- HTTP header `Authorization: APIKEY <api-key>`
- HTTP header `X-API-Key: <api-key>`
- Query string parameter `api_key=<api-key>`
- Cookie `Cookie: APIKEY=<api-key>;`

`admin` API keys are only accepted in the (default) HTTP header `Authorization: Bearer <api-key>`.

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
  name: talker-api-protection
spec:
  hosts:
  - talker-api.127.0.0.1.nip.io
  authentication:
    "members-authorization-header":
      apiKey:
        selector:
          matchLabels:
            group: members
      credentials:
        authorizationHeader:
          prefix: APIKEY # instead of the default prefix 'Bearer'
    "members-custom-header":
      apiKey:
        selector:
          matchLabels:
            group: members
      credentials:
        customHeader:
          name: X-API-Key
    "members-query-string-param":
      apiKey:
        selector:
          matchLabels:
            group: members
      credentials:
        queryString:
          name: api_key
    "members-cookie":
      apiKey:
        selector:
          matchLabels:
            group: members
      credentials:
        cookie:
          name: APIKEY
    "admins":
      apiKey:
        selector:
          matchLabels:
            group: admins
EOF
```

## ❻ Create the API keys

For a member user:

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: members
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

For an admin user:

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-2
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: admins
stringData:
  api_key: 7BNaTmYGItSzXiwQLNHu82+x52p1XHgY
type: Opaque
EOF
```

## ❼ Consume the API

As member user, passing the API key in the `Authorization` header:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As member user, passing the API key in the custom `X-API-Key` header:

```sh
curl -H 'X-API-Key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As member user, passing the API key in the query string parameter `api_key`:

```sh
curl "http://talker-api.127.0.0.1.nip.io:8000/hello?api_key=ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx"
# HTTP/1.1 200 OK
```

As member user, passing the API key in the `APIKEY` cookie header:

```sh
curl -H 'Cookie: APIKEY=ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx;foo=bar' http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As admin user:

```sh
curl -H 'Authorization: Bearer 7BNaTmYGItSzXiwQLNHu82+x52p1XHgY' http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Missing the API key:

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: APIKEY realm="members-authorization-header"
# www-authenticate: X-API-Key realm="members-custom-header"
# www-authenticate: api_key realm="members-query-string-param"
# www-authenticate: APIKEY realm="members-cookie"
# www-authenticate: Bearer realm="admins"
# x-ext-auth-reason: {"admins":"credential not found","members-authorization-header":"credential not found","members-cookie":"credential not found","members-custom-header":"credential not found","members-query-string-param":"credential not found"}
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete secret/api-key-1
kubectl delete secret/api-key-2
kubectl delete authconfig/talker-api-protection
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
