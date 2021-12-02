# User guide: Authentication with Kubernetes tokens (TokenReview API)

<details>
  <summary><strong>Feature:</strong> Identity verification & authentication → <a href="./../features.md#kubernetes-tokenreview-identitykubernetes">Kubernetes TokenReview</a></summary>

  Authorino can verify Kubernetes-valid access tokens (using Kubernetes [TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1) API).

  These tokens can be either `ServiceAccount` tokens or any valid user access tokens issued to users of the Kubernetes server API.

  The `audiences` claim of the token must include the requested host and port of the protected API (default), or all audiences specified in `spec.identity.kubernetes.audiences` of the `AuthConfig`.

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- Kubernetes user with permission to create `TokenRequest`s (to consume the API from ouside the cluster)
- [yq](https://github.com/mikefarah/yq) (to parse your `~/.kube/config` file to extract user authentication data)

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
  clusterWide: true
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
EOF
```

The command above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `cluster-wide` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

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
  - envoy.authorino.svc.cluster.local
  identity:
  - name: authorized-service-accounts
    kubernetes:
      audiences:
      - talker-api
EOF
```

## 7. Create a `ServiceAccount`

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-consumer-1
EOF
```

## 8. Consume the API from outside the cluster

Get the Kubernetes API base endpoint and current Kubernetes user, and save the user's TLS certificate and TLS key to file:

```sh
CURRENT_K8S_CONTEXT=$(kubectl config view -o json | jq -r '."current-context"')
CURRENT_K8S_USER=$(kubectl config view -o json | jq -r --arg K8S_CONTEXT "${CURRENT_K8S_CONTEXT}"  '.contexts[] | select(.name == $K8S_CONTEXT) | .context.user')
CURRENT_K8S_CLUSTER=$(kubectl config view -o json | jq -r --arg K8S_CONTEXT "${CURRENT_K8S_CONTEXT}"  '.contexts[] | select(.name == $K8S_CONTEXT) | .context.cluster')
KUBERNETES_API=$(kubectl config view -o json | jq -r --arg K8S_CLUSTER "${CURRENT_K8S_CLUSTER}" '.clusters[] | select(.name == $K8S_CLUSTER) | .cluster.server')

yq r ~/.kube/config "users(name==$CURRENT_K8S_USER).user.client-certificate-data" | base64 -d > /tmp/kind-cluster-user-cert.pem
yq r ~/.kube/config "users(name==$CURRENT_K8S_USER).user.client-key-data" | base64 -d > /tmp/kind-cluster-user-cert.key
```

Use the Kubernetes user's client TLS certificate to obtain a short-lived access token for the `api-consumer-1` `ServiceAccount`:

```sh
export ACCESS_TOKEN=$(curl -k -X "POST" "$KUBERNETES_API/api/v1/namespaces/authorino/serviceaccounts/api-consumer-1/token" \
     --cert /tmp/kind-cluster-user-cert.pem --key /tmp/kind-cluster-user-cert.key \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d $'{ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": { "audiences": ["talker-api"], "expirationSeconds": 600 } }' | jq -r '.status.token')
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

## 9. Consume the API from inside the cluster

Deploy an application that consumes an endpoint of the Talker API, in a loop, every 10 seconds. The application uses a short-lived service account token mounted inside the container using Kubernetes [Service Account Token Volume Projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection) to authenticate.

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Pod
metadata:
  name: api-consumer
spec:
  containers:
  - name: api-consumer
    image: quay.io/3scale/authorino:api-consumer
    command: ["./run"]
    args:
      - --endpoint=http://envoy.authorino.svc.cluster.local:8000/hello
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
kubectl -n authorino logs -f api-consumer
# Sending...
# 200
# 200
# 200
# 200
# ...
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
