# User guide: Injecting data in the request

<details>
  <summary>
    <strong>Features:</strong>
    <ul>
      <li>Dynamic response → <a href="./../features.md#json-injection-responsejson">JSON injection</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
    </ul>
  </summary>

  Inject serialized custom JSON objects as HTTP request headers. Values can be static or fetched from the [Authorization JSON](./../architecture.md#the-authorization-json).

  Check out as well the user guide about [Authentication with API keys](./api-key-authentication.md).

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

The following defines a JSON object to be injected as an added HTTP header into the request, named after the response config `x-ext-auth-data`. The object includes 3 properties:
1. a static value `authorized: true`;
2. a dynamic value `request-time`, from Envoy-supplied contextual data present in the Authorization JSON; and
3. a greeting message `geeting-message` that interpolates a dynamic value read from an annotation of the Kubernetes `Secret` resource that represents the API key used to authenticate into a static string.

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
  - name: friends
    apiKey:
      labelSelectors:
        group: friends
    credentials:
      in: authorization_header
      keySelector: APIKEY
  response:
  - name: x-ext-auth-data
    json:
      properties:
      - name: authorized
        value: true
      - name: request-time
        valueFrom:
          authJSON: context.request.time.seconds
      - name: geeting-message
        valueFrom:
          authJSON: Hello, {auth.identity.metadata.annotations.auth-data\/name}!
EOF
```

Check out the docs for information about the common feature [JSON paths](./../features.md#common-feature-json-paths-valuefromauthjson) for reading from the [Authorization JSON](./../architecture.md#the-authorization-json).

## 7. Create an API key

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.3scale.net/managed-by: authorino
    group: friends
  annotations:
    auth-data/name: Rita
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

## 8. Consume the API

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# {
#   "method": "GET",
#   "path": "/hello",
#   "query_string": null,
#   "body": "",
#   "headers": {
#     …
#     "X-Ext-Auth-Data": "{\"authorized\":true,\"geeting-message\":\"Hello, Rita!\",\"request-time\":1637954644}",
#   },
#   …
# }
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
