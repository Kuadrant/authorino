# User guide: Open Policy Agent (OPA) Rego policies

Leverage the power of Open Policy Agent (OPA) policies, evaluated against Authorino's Authorization JSON in a built-in runtime compiled together with Authorino; pre-cache policies defined in Rego language inline or fetched from an external policy registry.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Authorization → <a href="./../features.md#open-policy-agent-opa-rego-policies-authorizationopa">Open Policy Agent (OPA) Rego policies</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
    </ul>
  </summary>

  Authorino supports [Open Policy Agent](https://www.openpolicyagent.org) policies, either inline defined in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language) as part of the `AuthConfig` or fetched from an external endpoint, such as an OPA Policy Registry.

  Authorino's built-in OPA module precompiles the policies in reconciliation-time and cache them for fast evaluation in request-time, where they receive the Authorization JSON as input.

  Check out as well the user guide about [Authentication with API keys](./api-key-authentication.md).

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
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
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

In this example, we will use OPA to implement a read-only policy for requests coming from outside a trusted network (IP range 192.168.1/24).

The implementation relies on the [`X-Forwarded-For`](https://datatracker.ietf.org/doc/html/rfc7239) HTTP header to read the client's IP address.

_Optional._ Set [`use_remote_address: true`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-field-extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-use-remote-address) in the Envoy route configuration, so the proxy will append its IP address instead of run in transparent mode. This setting will also ensure real remote address of the client connection passed in the [`x-envoy-external-address`](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#config-http-conn-man-headers-x-envoy-external-address) HTTP header, which can be used to simplify the read-only policy in remote environment.

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
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
          trusted_network { regex.match(`192\.168\.1\.\d+`, ips[0]) }

          allow { trusted_network }
          allow { not trusted_network; input.context.request.http.method == "GET" }
EOF
```

## 6. Create an API key

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

## 7. Consume the API

Inside the trusted network:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 192.168.1.10' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 192.168.1.10' \
     -X POST \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Outside the trusted network:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 123.45.6.78' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' \
     -H 'X-Forwarded-For: 123.45.6.78' \
     -X POST \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
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
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
