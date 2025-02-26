# User guide: Fetching auth metadata from external sources

Get online data from remote HTTP services to enhance authorization rules.

<details markdown="1">
  <summary>
    <strong>Authorino capabilities featured in this guide:</strong>
    <ul>
      <li>External auth metadata → <a href="../features.md#http-getget-by-post-metadatahttp">HTTP GET/GET-by-POST</a></li>
      <li>Identity verification & authentication → <a href="../features.md#api-key-authenticationapikey">API key</a></li>
      <li>Authorization → <a href="../features.md#open-policy-agent-opa-rego-policies-authorizationopa">Open Policy Agent (OPA) Rego policies</a></li>
    </ul>
  </summary>

  You can configure Authorino to fetch additional metadata from external sources in request-time, by sending either GET or POST request to an HTTP service. The service is expected to return a JSON content which is appended to the [Authorization JSON](../architecture.md#the-authorization-json), thus becoming available for usage in other configs of the Auth Pipeline, such as in authorization policies or custom responses.

  URL, parameters and headers of the request to the external source of metadata can be configured, including with dynamic values. Authentication between Authorino and the service can be set as part of these configuration options, or based on shared authentication token stored in a Kubernetes `Secret`.

  Check out as well the user guides about [Authentication with API keys](api-key-authentication.md) and [Open Policy Agent (OPA) Rego policies](opa-authorization.md).

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

<br/>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

<br/>

The next steps walk you through installing Authorino, deploying and configuring a sample service called **Talker API** to be protected by the authorization service.

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

In this example, we will implement a geofence policy for the API, using OPA and metadata fetching from an external service that returns geolocalization JSON data for a given IP address. The policy establishes that only `GET` requests are allowed and the path of the request should be in the form `/{country-code}/*`, where `{country-code}` is the 2-character code of the country where the client is identified as being physically present.

The implementation relies on the [`X-Forwarded-For`](https://datatracker.ietf.org/doc/html/rfc7239) HTTP header to read the client's IP address.

<table>
  <tbody>
    <tr>
      <td>
        <b><i>Kuadrant users –</i></b>
        Remember to create an <a href="https://docs.kuadrant.io/latest/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> instead of an AuthConfig.
        For more, see <a href="https://docs.kuadrant.io/latest/kuadrant-operator/doc/overviews/auth">Kuadrant auth</a>.
      </td>
    </tr>
  </tbody>
</table>

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta3
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api.127.0.0.1.nip.io
  authentication:
    "friends":
      apiKey:
        selector:
          matchLabels:
            group: friends
      credentials:
        authorizationHeader:
          prefix: APIKEY
  metadata:
    "geo":
      http:
        urlExpression: |
          'http://ip-api.com/json/' + request.headers['x-forwarded-for'].split(',')[0] + '?fields=countryCode'
        headers:
          "Accept":
            expression: '"application/json"'
  authorization:
    "geofence":
      opa:
        rego: |
          import input.context.request.http

          allow {
            http.method = "GET"
            split(http.path, "/") = [_, requested_country, _]
            lower(requested_country) == lower(object.get(input.auth.metadata.geo, "countryCode", ""))
          }
EOF
```

Check out the docs about using [Common Expression Language (CEL)](../features.md#common-feature-common-expression-language-cel) for reading from the [Authorization JSON](../architecture.md#the-authorization-json).

## ❻ Create an API key

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: friends
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

## ❼ Consume the API

From an IP address assigned to the United Kingdom of Great Britain and Northern Ireland (country code GB):

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api.127.0.0.1.nip.io:8000/gb/hello -i
# HTTP/1.1 200 OK
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api.127.0.0.1.nip.io:8000/it/hello -i
# HTTP/1.1 403 Forbidden
```

From an IP address assigned to Italy (country code IT):

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 109.112.34.56' \
     http://talker-api.127.0.0.1.nip.io:8000/gb/hello -i
# HTTP/1.1 403 Forbidden
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 109.112.34.56' \
     http://talker-api.127.0.0.1.nip.io:8000/it/hello -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete secret/api-key-1
kubectl delete authconfig/talker-api-protection
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
