# User guide: HTTP "Basic" Authentication (RFC 7235)

Turn Authorino API key `Secret`s settings into HTTP basic auth.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
        <li>Authorization → <a href="./../features.md#json-pattern-matching-authorization-rules-authorizationjson">JSON pattern-matching authorization rules</a></li>
    </ul>
  </summary>

  HTTP "Basic" Authentication ([RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235)) is not recommended if you can afford other more secure methods such as OpenID Connect. To support legacy nonetheless it is sometimes necessary to implement it.

  In Authorino, HTTP "Basic" Authentication can be modeled leveraging the API key authentication feature (stored as Kubernetes `Secret`s with an `api_key` entry and labeled to match selectors specified in `spec.identity.apiKey.labelSelectors` of the `AuthConfig`).

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
  - name: http-basic-auth
    apiKey:
      labelSelectors:
        group: users
    credentials:
      in: authorization_header
      keySelector: Basic
  authorization:
  - name: acl
    json:
      conditions:
      - selector: context.request.http.path
        operator: eq
        value: /bye
      rules:
      - selector: context.request.http.headers.authorization.@extract:{"pos":1}|@base64:decode|@extract:{"sep":":"}
        operator: eq
        value: john
EOF
```

The config specifies an Access Control List (ACL), by which only the user `john` is authorized to consume the `/bye` endpoint of the API.

Check out the docs for information about the common feature [JSON paths](./../features.md#common-feature-json-paths-valuefromauthjson) for reading from the [Authorization JSON](./../architecture.md#the-authorization-json), including the description of the `@extract` and `@base64` string modifiers.

## 7. Create user credentials

To create credentials for HTTP "Basic" Authentication, store each `username:password`, base64-encoded, in the `api_key` value of the Kubernetes `Secret` resources. E.g.:

```sh
printf "john:ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" | base64
# am9objpuZHlCenJlVXpGNHpxRFFzcVNQTUhrUmhyaUVPdGNSeA==
```

Create credentials for user John:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: basic-auth-1
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: users
stringData:
  api_key: am9objpuZHlCenJlVXpGNHpxRFFzcVNQTUhrUmhyaUVPdGNSeA== # john:ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

Create credentials for user Jane:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: basic-auth-2
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: users
stringData:
  api_key: amFuZTpkTnNScnNhcHkwbk5Dd210NTM3ZkhGcHl4MGNCc0xFcA== # jane:dNsRrsapy0nNCwmt537fHFpyx0cBsLEp
type: Opaque
EOF
```

## 8. Consume the API

As John (authorized in the ACL):

```sh
curl -u john:ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -u john:ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx http://talker-api-authorino.127.0.0.1.nip.io:8000/bye
# HTTP/1.1 200 OK
```

As Jane (NOT authorized in the ACL):

```sh
curl -u jane:dNsRrsapy0nNCwmt537fHFpyx0cBsLEp http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -u jane:dNsRrsapy0nNCwmt537fHFpyx0cBsLEp http://talker-api-authorino.127.0.0.1.nip.io:8000/bye -i
# HTTP/1.1 403 Forbidden
```

With an invalid user/password:

```sh
curl -u unknown:invalid http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="http-basic-auth"
```

## 9. Revoke access to the API

```sh
kubectl -n authorino delete secret/basic-auth-1
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
