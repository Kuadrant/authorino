# User guide: Hello World

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

The next steps walk you through installing Authorino, deploying and configuring a sample service called **Talker API** to be protected by the authorization service.

## ❶ Create the namespace

```sh
kubectl create namespace hello-world
# namespace/hello-world created
```

## ❷ Deploy the Talker API

The **Talker API** is a simple HTTP service that echoes back in the response whatever it gets in the request. We will use it in this guide as the sample service to be protected by Authorino.

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
# deployment.apps/talker-api created
# service/talker-api created
```

## ❸ Setup Envoy

The following bundle from the Authorino examples deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Talker API behind the reverse-proxy, with external authorization enabled with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/hello-world/envoy-deploy.yaml
# configmap/envoy created
# deployment.apps/envoy created
# service/envoy created
```

The command above creates an `Ingress` with host name `talker-api.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8000 to the Envoy service running inside the cluster:

```sh
kubectl -n hello-world port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
```

## ❹ Consume the API (unprotected)

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

## ❺ Protect the API

### Install the Authorino Operator

```sh
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
```

### Deploy Authorino

The following command will request an instance of Authorino as a separate service[^1] that watches for `AuthConfig` resources in the `hello-world` namespace[^2], with TLS disabled[^3].

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/hello-world/authorino.yaml
# authorino.operator.authorino.kuadrant.io/authorino created
```

[^1]: In contrast to a dedicated sidecar of the protected service and other architectures. Check out __Architecture > [Topologies](../architecture.md#topologies)__ for all options.
[^2]: `namespaced` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^3]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.


## ❻ Consume the API behind Envoy and Authorino

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 404 Not Found
# x-ext-auth-reason: Service not found
```

Authorino does not know about the `talker-api.127.0.0.1.nip.io` host, hence the `404 Not Found`. Let's teach Authorino about this host by applying an `AuthConfig`.

## ❼ Apply the `AuthConfig`

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced:

<table>
  <tbody>
    <tr>
      <td>
        <b><i>Kuadrant users –</i></b>
        Remember to create an <a href="https://docs.kuadrant.io/latest/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> instead of an AuthConfig.
        For more, see <a href="https://docs.kuadrant.io/latest/kuadrant-operator/doc/overviews/auth">Kuadrant auth</a>.
      </td>
    </tr>
  </tbody>
</table>

```sh
kubectl -n hello-world apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/hello-world/authconfig.yaml
# authconfig.authorino.kuadrant.io/talker-api-protection created
```

## ❽ Consume the API without credentials

```sh
curl http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: APIKEY realm="api-clients"
# x-ext-auth-reason: credential not found
```

## Grant access to the API with a tailor-made security scheme

Check out other [user guides](../user-guides.md) for several use-cases of authentication and authorization, and the instructions to implement them using Authorino.

A few examples of available ser guides:

- [Authentication with API keys](api-key-authentication.md)
- [Authentication with JWTs and OpenID Connect Discovery](oidc-jwt-authentication.md)
- [Authentication with Kubernetes tokens (TokenReview API)](kubernetes-tokenreview.md)
- [Authorization with Open Policy Agent (OPA) Rego policies](opa-authorization.md)
- [Authorization with simple JSON pattern-matching rules (e.g. JWT claims)](json-pattern-matching-authorization.md)
- [Authorization with Kubernetes RBAC (SubjectAccessReview API)](kubernetes-subjectaccessreview.md)
- [Fetching auth metadata from external sources](external-metadata.md)
- [Token normalization](token-normalization.md)

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
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
