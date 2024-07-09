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

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Common feature → [Caching](../features.md#common-feature-caching-cache)
  - Identity verification & authentication → [Anonymous access](../features.md#anonymous-access-authenticationanonymous)
  - External auth metadata → [HTTP GET/GET-by-POST](../features.md#http-getget-by-post-metadatahttp)
  - Authorization → [Open Policy Agent (OPA) Rego policies](../features.md#open-policy-agent-opa-rego-policies-authorizationopa)
  - Dynamic response → [JSON injection](../features.md#json-injection-responsesuccessheadersdynamicmetadatajson)

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

The example below enables caching for the external source of metadata, which in this case, for convenience, is the same upstream API protected by Authorino (i.e. the Talker API), though consumed directly by Authorino, without passing through the proxy. This API generates a `uuid` random hash that it injects in the JSON response. This value is different in every request processed by the API.

The example also enables caching of returned OPA virtual documents. `cached-authz` is a trivial Rego policy that always grants access, but generates a timestamp, which Authorino will cache.

In both cases, the path of the HTTP request is used as cache key. I.e., whenever the path repeats, Authorino reuse the values stored previously in each cache table (`cached-metadata` and `cached-authz`), respectively saving a request to the external source of metadata and the evaluation of the OPA policy. Cache entries will expire in both cases after 60 seconds they were stored in the cache.

The cached values will be visible in the response returned by the Talker API in `x-authz-data` header injected by Authorino. This way, we can tell when an existing value in the cache was used and when a new one was generated and stored.

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
    "anonymous":
      anonymous: {}
  metadata:
    "cached-metadata":
      http:
        url: "http://talker-api.default.svc.cluster.local:3000/metadata/{context.request.http.path}"
      cache:
        key:
          selector: context.request.http.path
        ttl: 60
  authorization:
    "cached-authz":
      opa:
        rego: |
          now = time.now_ns()
          allow = true
        allValues: true
      cache:
        key:
          selector: context.request.http.path
        ttl: 60
  response:
    success:
      headers:
        "x-authz-data":
          json:
            properties:
              "cached-metadata":
                selector: auth.metadata.cached-metadata.uuid
              "cached-authz":
                selector: auth.authorization.cached-authz.now
EOF
```

## ❻ Consume the API

1. To `/hello`

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/hello
# […]
#  "X-Authz-Data": "{\"cached-authz\":\"1649343067462380300\",\"cached-metadata\":\"92c111cd-a10f-4e86-8bf0-e0cd646c6f79\"}",
# […]
```

2. To a different path

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/goodbye
# […]
#  "X-Authz-Data": "{\"cached-authz\":\"1649343097860450300\",\"cached-metadata\":\"37fce386-1ee8-40a7-aed1-bf8a208f283c\"}",
# […]
```

3. To `/hello` again _before_ the cache entry expires (60 seconds from the first request sent to this path)

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/hello
# […]
#  "X-Authz-Data": "{\"cached-authz\":\"1649343067462380300\",\"cached-metadata\":\"92c111cd-a10f-4e86-8bf0-e0cd646c6f79\"}",  <=== same cache-id as before
# […]
```

4. To `/hello` again _after_ the cache entry expires (60 seconds from the first request sent to this path)

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/hello
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
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
