# User guide: Authentication with API keys

Issue API keys stored in Kubernetes `Secret`s for clients to authenticate with your protected hosts.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
    </ul>
  </summary>

  In Authorino, API keys are stored as Kubernetes `Secret`s. Each resource must contain an `api_key` entry with the value of the API key, and labeled to match the selectors specified in `spec.identity.apiKey.labelSelectors` of the `AuthConfig`.

  API key `Secret`s must also include labels that match the `secretLabelSelector` field of the Authorino instance. See [Resource reconciliation and status update](../architecture.md#resource-reconciliation-and-status-update) for details.

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
EOF
```

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
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

## 8. Consume the API

With a valid API key:

```sh
curl -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

With missing or invalid API key:

```sh
curl -H 'Authorization: APIKEY invalid' http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: APIKEY realm="friends"
# x-ext-auth-reason: the API Key provided is invalid
```

## 9. Delete an API key (revoke access to the API)

```sh
kubectl -n authorino delete secret/api-key-1
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
