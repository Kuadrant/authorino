# User guide: Hello World

<br/>

## Requirements

- Kubernetes server

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-trial
```

## 1. Create the namespace

```sh
kubectl create namespace hello-world
# namespace/hello-world created
```

## 2. Deploy the Talker API

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
# deployment.apps/talker-api created
# service/talker-api created
```

## 3. Setup Envoy

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/hello-world/envoy-deploy.yaml
# configmap/envoy created
# deployment.apps/envoy created
# service/envoy created
```

Forward requests on port 8000 to the Envoy pod running inside the cluster:

```sh
kubectl -n hello-world port-forward deployment/envoy 8000:8000 &
```

## 4. Consume the API (unprotected)

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

## 5. Protect the API

### Install the Authorino Operator

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

### Deploy Authorino

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/hello-world/authorino.yaml
# authorino.operator.authorino.kuadrant.io/authorino created
```

The command above will deploy Authorino as a separate service (in contrast to as a sidecar of the Talker API and other architectures). For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 6. Consume the API behind Envoy and Authorino

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 404 Not Found
# x-ext-auth-reason: Service not found
```

Authorino does not know about the `talker-api-authorino.127.0.0.1.nip.io` host, hence the `404 Not Found`. Teach it by applying an `AuthConfig`.

## 7. Apply an `AuthConfig`

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/hello-world/authconfig.yaml
# authconfig.authorino.kuadrant.io/talker-api-protection created
```

## 8. Consume the API without credentials

```sh
curl http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: APIKEY realm="api-clients"
# x-ext-auth-reason: credential not found
```

## Grant access to the API with a tailor-made security scheme

Check out other [user guides](./../user-guides.md) for several AuthN/AuthZ use-cases and instructions to implement them using Authorino. A few examples are:

- [Authentication with API keys](./api-key-authentication.md)
- [Authentication with JWTs and OpenID Connect Discovery](./oidc-jwt-authentication.md)
- [Authentication with Kubernetes tokens (TokenReview API)](./kubernetes-tokenreview.md)
- [Authorization with Open Policy Agent (OPA) Rego policies](./opa-authorization.md)
- [Authorization with simple JSON pattern-matching rules (e.g. JWT claims)](./json-pattern-matching-authorization.md)
- [Authorization with Kubernetes RBAC (SubjectAccessReview API)](./kubernetes-subjectaccessreview.md)
- [Fetching auth metadata from external sources](./external-metadata.md)
- [Token normalization](./token-normalization.md)

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-trial
```

Otherwise, delete the namespaces created in step 1 and 5:

```sh
kubectl delete namespace hello-world
kubectl delete namespace authorino-operator
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
