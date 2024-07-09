# User guide: HTTP "Basic" Authentication (RFC 7235)

Turn Authorino API key `Secret`s settings into HTTP basic auth.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Identity verification & authentication → [API key](../features.md#api-key-authenticationapikey)
  - Authorization → [Pattern-matching authorization](../features.md#pattern-matching-authorization-authorizationpatternmatching)

  HTTP "Basic" Authentication ([RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235)) is not recommended if you can afford other more secure methods such as OpenID Connect. To support legacy nonetheless it is sometimes necessary to implement it.

  In Authorino, HTTP "Basic" Authentication can be modeled leveraging the API key authentication feature (stored as Kubernetes `Secret`s with an `api_key` entry and labeled to match selectors specified in `spec.identity.apiKey.selector` of the `AuthConfig`).

  Check out as well the user guide about [Authentication with API keys](api-key-authentication.md).

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

<br/>

The next steps walk you through installing Authorino, deploying and configuring a sample service called **Talker API** to be protected by the authorization service.

<table>
  <thead>
    <tr>
      <th>Using Kuadrant</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>
        <p>If you are a user of <a href="https://kuadrant.io">Kuadrant</a> and already have your workload cluster configured and sample service application deployed, as well as your Gateway API network resources applied to route traffic to your service, skip straight to step ❺.</p>
        <p>At step ❺, instead of creating an <code>AuthConfig</code> custom resource, create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> one. The schema of the AuthConfig's <code>spec</code> matches the one of the AuthPolicy's, except <code>spec.host</code>, which is not available in the Kuadrant AuthPolicy. Host names in a Kuadrant AuthPolicy are inferred automatically from the Kubernetes network object referred in <code>spec.targetRef</code> and route selectors declared in the policy.</p>
        <p>For more about using Kuadrant to enforce authorization, check out <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.</p>
      </td>
    </tr>
  </tbody>
</table>

<br/>

## ❶ Install the Authorino Operator (cluster admin required)

The following command will install the [Authorino Operator](http://github.com/kuadrant/authorino-operator) in the Kubernetes cluster. The operator manages instances of the Authorino authorization service.

```sh
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
```

## ❷ Deploy Authorino

The following command will request an instance of Authorino as a separate service[^1] that watches for `AuthConfig` resources in the `default` namespace[^2], with TLS disabled[^3].

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

[^1]: In contrast to a dedicated sidecar of the protected service and other architectures. Check out __Architecture > [Topologies](../architecture.md#topologies)__ for all options.
[^2]: `namespaced` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^3]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.

## ❸ Deploy the Talker API

The **Talker API** is a simple HTTP service that echoes back in the response whatever it gets in the request. We will use it in this guide as the sample service to be protected by Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## ❹ Setup Envoy

The following bundle from the Authorino examples deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Talker API behind the reverse-proxy, with external authorization enabled with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The command above creates an `Ingress` with host name `talker-api.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8000 to the Envoy service running inside the cluster:

```sh
kubectl port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
```

## ❺ Create an `AuthConfig`

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced.

The config uses API Key secrets to store base64-encoded `username:password` HTTP "Basic" authentication credentials. The config also specifies an Access Control List (ACL) by which only user `john` is authorized to consume the `/bye` endpoint of the API.

<table>
  <tbody>
    <tr>
      <td>
        <b><i>Kuadrant users –</i></b>
        Remember to create an <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> instead of an AuthConfig.
        For more, see <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.
      </td>
    </tr>
  </tbody>
</table>

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api.127.0.0.1.nip.io
  authentication:
    "http-basic-auth":
      apiKey:
        selector:
          matchLabels:
            group: users
      credentials:
        authorizationHeader:
          prefix: Basic
  authorization:
    "acl":
      when:
      - selector: context.request.http.path
        operator: eq
        value: /bye
      patternMatching:
        patterns:
        - selector: context.request.http.headers.authorization.@extract:{"pos":1}|@base64:decode|@extract:{"sep":":"}
          operator: eq
          value: john
EOF
```

Check out the docs for information about the common feature [JSON paths](../features.md#common-feature-json-paths-selector) for reading from the [Authorization JSON](../architecture.md#the-authorization-json), including the description of the string modifiers `@extract` and `@case` used above. Check out as well the common feature [Conditions](../features.md#common-feature-conditions-when) about skipping parts of an `AuthConfig` in the auth pipeline based on context.

## ❻ Create user credentials

To create credentials for HTTP "Basic" Authentication, store each `username:password`, base64-encoded, in the `api_key` value of the Kubernetes `Secret` resources. E.g.:

```sh
printf "john:ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" | base64
# am9objpuZHlCenJlVXpGNHpxRFFzcVNQTUhrUmhyaUVPdGNSeA==
```

Create credentials for user John:

```sh
kubectl apply -f -<<EOF
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
kubectl apply -f -<<EOF
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

## ❼ Consume the API

As John (authorized in the ACL):

```sh
curl -u john:ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -u john:ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx http://talker-api.127.0.0.1.nip.io:8000/bye
# HTTP/1.1 200 OK
```

As Jane (NOT authorized in the ACL):

```sh
curl -u jane:dNsRrsapy0nNCwmt537fHFpyx0cBsLEp http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -u jane:dNsRrsapy0nNCwmt537fHFpyx0cBsLEp http://talker-api.127.0.0.1.nip.io:8000/bye -i
# HTTP/1.1 403 Forbidden
```

With an invalid user/password:

```sh
curl -u unknown:invalid http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="http-basic-auth"
```

## ❽ Revoke access to the API

```sh
kubectl delete secret/basic-auth-1
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete secret/basic-auth-1
kubectl delete secret/basic-auth-2
kubectl delete authconfig/talker-api-protection
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
