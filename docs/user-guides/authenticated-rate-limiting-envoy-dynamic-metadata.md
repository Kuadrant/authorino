# User guide: Authenticated rate limiting (with Envoy Dynamic Metadata)

Provide Envoy with dynamic metadata about the external authorization process to be injected into the rate limiting filter.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Dynamic response → Response wrappers → <a href="./../features.md#envoy-dynamic-metadata">Envoy Dynamic Metadata</a></li>
      <li>Dynamic response → <a href="./../features.md#json-injection-responsejson">JSON injection</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
    </ul>
  </summary>

  Dynamic JSON objects built out of static values and values fetched from the [Authorization JSON](./../architecture.md#the-authorization-json) can be wrapped to be returned to the reverse-proxy as Envoy Well Known Dynamic Metadata content. Envoy can use those to inject data returned by the external authorization service into the other filters, such as the rate limiting filter.

  Check out as well the user guides about [Injecting data in the request](./injecting-data.md) and [Authentication with API keys](./api-key-authentication.md).

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

The command above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `namespaced` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 4. Deploy Limitador

[Limitador](https://github.com/kuadrant/limitador) is a lightweight rate limiting service that can be used with Envoy.

On this bundle, we will deploy Limitador pre-configured to limit requests to the `talker-api` domain up to 5 requests per interval of 60 seconds per `user_id`. Envoy will be configured to recognize the presence of Limitador and activate it on requests to the Talker API.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/limitador/limitador-deploy.yaml
```

## 5. Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#1-setup-envoy) page. For a simpler and straighforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl port-forward deployment/envoy 8000:8000 &
```

## 6. Create the `AuthConfig`

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
  - name: friends
    apiKey:
      selector:
        matchLabels:
          group: friends
    credentials:
      in: authorization_header
      keySelector: APIKEY
  response:
  - name: rate-limit
    wrapper: envoyDynamicMetadata
    wrapperKey: ext_auth_data # how this bit of dynamic metadata from the ext authz service is named in the Envoy config
    json:
      properties:
      - name: username
        valueFrom:
          authJSON: auth.identity.metadata.annotations.auth-data\/username
EOF
```

An annotation `auth-data/username` will be read from the Kubernetes `Secret`s storing valid API keys and passed as dynamic metadata `{ "ext_auth_data": { "username": «annotations.auth-data/username» } }`.

Check out the docs for information about the common feature [JSON paths](./../features.md#common-feature-json-paths-valuefromauthjson) for reading from the [Authorization JSON](./../architecture.md#the-authorization-json).

## 7. Create a couple of API keys

For user John:

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: friends
  annotations:
    auth-data/username: john
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

For user Jane:

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-2
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: friends
  annotations:
    auth-data/username: jane
stringData:
  api_key: 7BNaTmYGItSzXiwQLNHu82+x52p1XHgY
type: Opaque
EOF
```

## 8. Consume the API

As John:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Repeat the request a few more times within the 60-second time window, until the response status is `429 Too Many Requests`.

While the API is still limited to John, send requests as Jane:

```sh
curl -H 'Authorization: APIKEY 7BNaTmYGItSzXiwQLNHu82+x52p1XHgY' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
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
kubectl delete secret/api-key-2
kubectl delete authconfig/talker-api-protection
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/limitador/limitador-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
