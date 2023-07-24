# User guide: Authentication with Kubernetes tokens (TokenReview API)

Validate Kubernetes Service Account tokens to authenticate requests to your protected hosts.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#kubernetes-tokenreview-identitykubernetes">Kubernetes TokenReview</a></li>
    </ul>
  </summary>

  Authorino can verify Kubernetes-valid access tokens (using Kubernetes [TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1) API).

  These tokens can be either `ServiceAccount` tokens or any valid user access tokens issued to users of the Kubernetes server API.

  The `audiences` claim of the token must include the requested host and port of the protected API (default), or all audiences specified in `spec.identity.kubernetes.audiences` of the `AuthConfig`.

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- Kubernetes user with permission to create `TokenRequest`s (to consume the API from outside the cluster)
- [yq](https://github.com/mikefarah/yq) (to parse your `~/.kube/config` file to extract user authentication data)

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
  - envoy.default.svc.cluster.local
  identity:
  - name: authorized-service-accounts
    kubernetes:
      audiences:
      - talker-api
EOF
```

## 6. Create a `ServiceAccount`

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-consumer-1
EOF
```

## 7. Consume the API from outside the cluster

Obtain a short-lived access token for the `api-consumer-1` `ServiceAccount`:

```sh
export ACCESS_TOKEN=$(echo '{ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": { "audiences": ["talker-api"], "expirationSeconds": 600 } }' | kubectl create --raw /api/v1/namespaces/default/serviceaccounts/api-consumer-1/token -f - | jq -r .status.token)
```

Consume the API with a valid Kubernetes token:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Consume the API with the Kubernetes token expired (10 minutes):

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 401 Unauthorized
# www-authenticate: Bearer realm="authorized-service-accounts"
# x-ext-auth-reason: Not authenticated
```

## 8. Consume the API from inside the cluster

Deploy an application that consumes an endpoint of the Talker API, in a loop, every 10 seconds. The application uses a short-lived service account token mounted inside the container using Kubernetes [Service Account Token Volume Projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection) to authenticate.

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Pod
metadata:
  name: api-consumer
spec:
  containers:
  - name: api-consumer
    image: quay.io/kuadrant/authorino-examples:api-consumer
    command: ["./run"]
    args:
      - --endpoint=http://envoy.default.svc.cluster.local:8000/hello
      - --token-path=/var/run/secrets/tokens/api-token
      - --interval=10
    volumeMounts:
    - mountPath: /var/run/secrets/tokens
      name: talker-api-access-token
  serviceAccountName: api-consumer-1
  volumes:
  - name: talker-api-access-token
    projected:
      sources:
      - serviceAccountToken:
          path: api-token
          expirationSeconds: 7200
          audience: talker-api
EOF
```

Check the logs of `api-consumer`:

```sh
kubectl logs -f api-consumer
# Sending...
# 200
# 200
# 200
# 200
# ...
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl pod/api-consumer
kubectl serviceaccount/api-consumer-1
kubectl delete authconfig/talker-api-protection
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
