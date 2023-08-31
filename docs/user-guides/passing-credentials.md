# User guide: Passing credentials (`Authorization` header, cookie headers and others)

Customize where credentials are supplied in the request by each trusted source of identity.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#extra-auth-credentials-credentials">Auth credentials</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
    </ul>
  </summary>

  Authentication tokens can be supplied in the `Authorization` header, in a custom header, cookie or query string parameter.

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

In this example, `member` users can authenticate supplying the API key in any of 4 different ways:
- HTTP header `Authorization: APIKEY <api-key>`
- HTTP header `X-API-Key: <api-key>`
- Query string parameter `api_key=<api-key>`
- Cookie `Cookie: APIKEY=<api-key>;`

`admin` API keys are only accepted in the (default) HTTP header `Authorization: Bearer <api-key>`.

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
  - name: members-authorization-header
    apiKey:
      selector:
        matchLabels:
          group: members
    credentials:
      in: authorization_header
      keySelector: APIKEY # instead of the default prefix 'Bearer'
  - name: members-custom-header
    apiKey:
      selector:
        matchLabels:
          group: members
    credentials:
      in: custom_header
      keySelector: X-API-Key
  - name: members-query-string-param
    apiKey:
      selector:
        matchLabels:
          group: members
    credentials:
      in: query
      keySelector: api_key
  - name: members-cookie
    apiKey:
      selector:
        matchLabels:
          group: members
    credentials:
      in: cookie
      keySelector: APIKEY
  - name: admins
    apiKey:
      selector:
        matchLabels:
          group: admins
EOF
```

## 6. Create a couple API keys

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

## 7. Consume the API

As member user, passing the API key in the `Authorization` header:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As member user, passing the API key in the custom `X-API-Key` header:

```sh
curl -H 'X-API-Key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As member user, passing the API key in the query string parameter `api_key`:

```sh
curl "http://talker-api-authorino.127.0.0.1.nip.io:8000/hello?api_key=ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx"
# HTTP/1.1 200 OK
```

As member user, passing the API key in the `APIKEY` cookie header:

```sh
curl -H 'Cookie: APIKEY=ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx;foo=bar' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

As admin user:

```sh
curl -H 'Authorization: Bearer 7BNaTmYGItSzXiwQLNHu82+x52p1XHgY' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Missing the API key:

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
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
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
