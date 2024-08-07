# User guide: Open Policy Agent (OPA) Rego policies

Leverage the power of Open Policy Agent (OPA) policies, evaluated against Authorino's Authorization JSON in a built-in runtime compiled together with Authorino; pre-cache policies defined in Rego language inline or fetched from an external policy registry.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Authorization → [Open Policy Agent (OPA) Rego policies](../features.md#open-policy-agent-opa-rego-policies-authorizationopa)
  - Identity verification & authentication → [API key](../features.md#api-key-authenticationapikey)

  Authorino supports [Open Policy Agent](https://www.openpolicyagent.org) policies, either inline defined in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language) as part of the `AuthConfig` or fetched from an external endpoint, such as an OPA Policy Registry.

  Authorino's built-in OPA module precompiles the policies in reconciliation-time and cache them for fast evaluation in request-time, where they receive the Authorization JSON as input.

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

In this example, we will use OPA to implement a read-only policy for requests coming from outside a trusted network (IP range 192.168.1/24).

The implementation relies on the [`X-Forwarded-For`](https://datatracker.ietf.org/doc/html/rfc7239) HTTP header to read the client's IP address.[^5]

[^5]: You can also set [`use_remote_address: true`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-field-extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-use-remote-address) in the Envoy route configuration, so the proxy will append its IP address instead of run in transparent mode. This setting will also ensure real remote address of the client connection passed in the [`x-envoy-external-address`](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#config-http-conn-man-headers-x-envoy-external-address) HTTP header, which can be used to simplify the read-only policy in remote environment.

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
    "friends":
      apiKey:
        selector:
          matchLabels:
            group: friends
      credentials:
        authorizationHeader:
          prefix: APIKEY
  authorization:
    "read-only-outside":
      opa:
        rego: |
          ips := split(input.context.request.http.headers["x-forwarded-for"], ",")
          trusted_network { net.cidr_contains("192.168.1.1/24", ips[0]) }

          allow { trusted_network }
          allow { not trusted_network; input.context.request.http.method == "GET" }
EOF
```

## ❻ Create the API key

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

Inside the trusted network:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 192.168.1.10' \
     http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 192.168.1.10' \
     -X POST \
     http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Outside the trusted network:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 123.45.6.78' \
     http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 123.45.6.78' \
     -X POST \
     http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Unauthorized
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
