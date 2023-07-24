# User guide: Caching

Cache auth objects resolved at runtime for any configuration bit of an AuthConfig (i.e. any evaluator), of any phase (identity, metadata, authorization and dynamic response), for easy access in subsequent requests, whenever an arbitrary (user-defined) cache key repeats, until the cache entry expires.

This is particularly useful for configuration bits whose evaluation is significantly more expensive than accessing the cache. E.g.:

- Caching of metadata fetched from external sources in general
- Caching of previously validated identity access tokens (e.g. for OAuth2 opaque tokens that involve consuming the token introspection endpoint of an external auth server)
- Caching of complex Rego policies that involve sending requests to external services

Cases where one will **NOT** want to enable caching, due to relatively cheap compared to accessing and managing the cache:
- Validation of OIDC/JWT access tokens
- OPA/Rego policies that do not involve external requests
- JSON pattern-matching authorization
- Dynamic JSON responses
- Anonymous access

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Common feature → <a href="./../features.md#common-feature-caching-cache">Caching</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#anonymous-access-identityanonymous">Anonymous access</a></li>
      <li>External auth metadata → <a href="./../features.md#http-getget-by-post-metadatahttp">HTTP GET/GET-by-POST</a></li>
      <li>Authorization → <a href="./../features.md#open-policy-agent-opa-rego-policies-authorizationopa">Open Policy Agent (OPA) Rego policies</a></li>
      <li>Dynamic response → <a href="./../features.md#json-injection-responsejson">JSON injection</a></li>
    </ul>
  </summary>

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-tutorial
```

## 1. Install the Authorino Operator

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

## 2. Deploy the Talker API

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## 3. Deploy Authorino

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

The command above will deploy Authorino as a separate service (as opposed to a sidecar of the protected API and other architectures), in `namespaced` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#step-request-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 4. Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#step-setup-envoy) page. For a simpler and straightforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl port-forward deployment/envoy 8000:8000 &
```

## 5. Create the `AuthConfig`

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
  identity:
  - name: anonymous
    anonymous: {}
  metadata:
  - name: cached-metadata
    http:
      endpoint: http://talker-api.default.svc.cluster.local:3000/metadata/{context.request.http.path}
      method: GET
    cache:
      key:
        valueFrom: { authJSON: context.request.http.path }
      ttl: 60
  authorization:
  - name: cached-authz
    opa:
      inlineRego: |
        now = time.now_ns()
        allow = true
      allValues: true
    cache:
      key:
        valueFrom: { authJSON: context.request.http.path }
      ttl: 60
  response:
  - name: x-authz-data
    json:
      properties:
      - name: cached-metadata
        valueFrom: { authJSON: auth.metadata.cached-metadata.uuid }
      - name: cached-authz
        valueFrom: { authJSON: auth.authorization.cached-authz.now }
EOF
```

The example above enables caching for the external source of metadata, which in this case, for convenience, is the same upstream API protected by Authorino (i.e. the Talker API), though consumed directly by Authorino, without passing through the proxy. This API generates a `uuid` random hash that it injects in the JSON response. This value is different in every request processed by the API.

The example also enables caching of returned OPA virtual documents. `cached-authz` is a trivial Rego policy that always grants access, but generates a timestamp, which Authorino will cache.

In both cases, the path of the HTTP request is used as cache key. I.e., whenever the path repeats, Authorino reuse the values stored previously in each cache table (`cached-metadata` and `cached-authz`), respectively saving a request to the external source of metadata and the evaluation of the OPA policy. Cache entries will expire in both cases after 60 seconds they were stored in the cache.

The cached values will be visible in the response returned by the Talker API in `x-authz-data` header injected by Authorino. This way, we can tell when an existing value in the cache was used and when a new one was generated and stored.

## 6. Consume the API

1. To `/hello`

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# […]
#  "X-Authz-Data": "{\"cached-authz\":\"1649343067462380300\",\"cached-metadata\":\"92c111cd-a10f-4e86-8bf0-e0cd646c6f79\"}",
# […]
```

2. To a different path

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/goodbye
# […]
#  "X-Authz-Data": "{\"cached-authz\":\"1649343097860450300\",\"cached-metadata\":\"37fce386-1ee8-40a7-aed1-bf8a208f283c\"}",
# […]
```

3. To `/hello` again _before_ the cache entry expires (60 seconds from the first request sent to this path)

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# […]
#  "X-Authz-Data": "{\"cached-authz\":\"1649343067462380300\",\"cached-metadata\":\"92c111cd-a10f-4e86-8bf0-e0cd646c6f79\"}",  <=== same cache-id as before
# […]
```

4. To `/hello` again _after_ the cache entry expires (60 seconds from the first request sent to this path)

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# […]
#  "X-Authz-Data": "{\"cached-authz\":\"1649343135702743800\",\"cached-metadata\":\"e708a3a6-5caf-4028-ab5c-573ad9be7188\"}",  <=== different cache-id
# […]
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete authconfig/talker-api-protection
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
