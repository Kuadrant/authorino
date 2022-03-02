# User guide: Fetching auth metadata from external sources

Get online data from remote HTTP services to enhance authorization rules.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>External auth metadata → <a href="./../features.md#http-getget-by-post-metadatahttp">HTTP GET/GET-by-POST</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
      <li>Authorization → <a href="./../features.md#open-policy-agent-opa-rego-policies-authorizationopa">Open Policy Agent (OPA) Rego policies</a></li>
    </ul>
  </summary>

  You can configure Authorino to fetch additional metadata from external sources in request-time, by sending either GET or POST request to an HTTP service. The service is expected to return a JSON content which is appended to the [Authorization JSON](./../architecture.md#the-authorization-json), thus becoming available for usage in other configs of the Auth Pipeline, such as in authorization policies or custom responses.

  URL, parameters and headers of the request to the external source of metadata can be configured, including with dynamic values. Authentication between Authorino and the service can be set as part of these configuration options, or based on shared authentication token stored in a Kubernetes `Secret`.

  Check out as well the user guides about [Authentication with API keys](./api-key-authentication.md) and [Open Policy Agent (OPA) Rego policies](./opa-authorization.md).

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-trial
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

In this example, we will implement a geofence policy for the API, using OPA and metadata fetching from an external service that returns geolocalization JSON data for a given IP address. The policy establishes that only `GET` requests are allowed and the path of the request should be in the form `/{country-code}/*`, where `{country-code}` is the 2-character code of the country where the client is identified as in.

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
  - name: friends
    apiKey:
      labelSelectors:
        group: friends
    credentials:
      in: authorization_header
      keySelector: APIKEY
  metadata:
    - name: geo
      http:
        endpoint: http://ip-api.com/json/{context.request.http.headers.x-forwarded-for.@extract:{"sep":","}}?fields=countryCode
        method: GET
        headers:
        - name: Accept
          value: application/json
  authorization:
  - name: geofence
    opa:
      inlineRego: |
        import input.context.request.http

        allow {
          http.method = "GET"
          split(http.path, "/") = [_, requested_country, _]
          lower(requested_country) == lower(object.get(input.auth.metadata.geo, "countryCode", ""))
        }
EOF
```

Check out the docs for information about the common feature [JSON paths](./../features.md#common-feature-json-paths-valuefromauthjson) for reading from the [Authorization JSON](./../architecture.md#the-authorization-json), including the description of the `@extract` string modifier.

## 7. Create an API key

```sh
kubectl -n authorino apply -f -<<EOF
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

## 8. Consume the API

From an IP address assigned to the United Kingdom of Great Britain and Northern Ireland (country code GB):

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/gb/hello -i
# HTTP/1.1 200 OK
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/it/hello -i
# HTTP/1.1 403 Forbidden
```

From an IP address assigned to Italy (country code IT):

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 109.112.34.56' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/gb/hello -i
# HTTP/1.1 403 Forbidden
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 109.112.34.56' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/it/hello -i
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
