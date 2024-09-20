# User guide: Integration with Authzed/SpiceDB

Permission requests sent to a Google Zanzibar-based [Authzed/SpiceDB](https://authzed.com) instance, via gRPC.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Authorization → [SpiceDB](../features.md#spicedb-authorizationspicedb)
  - Identity verification & authentication → [API key](../features.md#api-key-authenticationapikey)
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
        <p>If you are a user of <a href="https://kuadrant.io">Kuadrant</a> and already have your workload cluster configured and sample service application deployed, as well as your Gateway API network resources applied to route traffic to your service, skip straight to step ❻.</p>
        <p>At step ❻, instead of creating an <code>AuthConfig</code> custom resource, create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> one. The schema of the AuthConfig's <code>spec</code> matches the one of the AuthPolicy's, except <code>spec.host</code>, which is not available in the Kuadrant AuthPolicy. Host names in a Kuadrant AuthPolicy are inferred automatically from the Kubernetes network object referred in <code>spec.targetRef</code> and route selectors declared in the policy.</p>
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

## ❺ Create the permission database

Create the namespace:

```sh
kubectl create namespace spicedb
```

Create the SpiceDB instance:

```sh
kubectl -n spicedb apply -f -<<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spicedb
  labels:
    app: spicedb
spec:
  selector:
    matchLabels:
      app: spicedb
  template:
    metadata:
      labels:
        app: spicedb
    spec:
      containers:
      - name: spicedb
        image: authzed/spicedb
        args:
        - serve
        - "--grpc-preshared-key"
        - secret
        - "--http-enabled"
        ports:
        - containerPort: 50051
        - containerPort: 8443
  replicas: 1
---
apiVersion: v1
kind: Service
metadata:
  name: spicedb
spec:
  selector:
    app: spicedb
  ports:
    - name: grpc
      port: 50051
      protocol: TCP
    - name: http
      port: 8443
      protocol: TCP
EOF
```

Forward local request to the SpiceDB service inside the cluster:

```sh
kubectl -n spicedb port-forward service/spicedb 8443:8443 2>&1 >/dev/null &
```

Create the permission schema:

```sh
curl -X POST http://localhost:8443/v1/schema/write \
  -H 'Authorization: Bearer secret' \
  -H 'Content-Type: application/json' \
  -d @- << EOF
{
  "schema": "definition blog/user {}\ndefinition blog/post {\n\trelation reader: blog/user\n\trelation writer: blog/user\n\n\tpermission read = reader + writer\n\tpermission write = writer\n}"
}
EOF
```

Create the relationships:

- `blog/user:emilia` → `writer` of `blog/post:1`
- `blog/user:beatrice` → `reader` of `blog/post:1`

```sh
curl -X POST http://localhost:8443/v1/relationships/write \
  -H 'Authorization: Bearer secret' \
  -H 'Content-Type: application/json' \
  -d @- << EOF
{
  "updates": [
    {
      "operation": "OPERATION_CREATE",
      "relationship": {
        "resource": {
          "objectType": "blog/post",
          "objectId": "1"
        },
        "relation": "writer",
        "subject": {
          "object": {
            "objectType": "blog/user",
            "objectId": "emilia"
          }
        }
      }
    },
    {
      "operation": "OPERATION_CREATE",
      "relationship": {
        "resource": {
          "objectType": "blog/post",
          "objectId": "1"
        },
        "relation": "reader",
        "subject": {
          "object": {
            "objectType": "blog/user",
            "objectId": "beatrice"
          }
        }
      }
    }
  ]
}
EOF
```

## ❺ Create an `AuthConfig`

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced.

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

Store the shared token for Authorino to authenticate with the SpiceDB instance in a Service:

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: spicedb
  labels:
    app: spicedb
stringData:
  grpc-preshared-key: secret
EOF
```

Create the AuthConfig:

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
    "blog-users":
      apiKey:
        selector:
          matchLabels:
            app: talker-api
      credentials:
        authorizationHeader:
          prefix: APIKEY
  authorization:
    "authzed-spicedb":
      spicedb:
        endpoint: spicedb.spicedb.svc.cluster.local:50051
        insecure: true
        sharedSecretRef:
          name: spicedb
          key: grpc-preshared-key
        subject:
          kind:
            value: blog/user
          name:
            selector: auth.identity.metadata.annotations.username
        resource:
          kind:
            value: blog/post
          name:
            selector: context.request.http.path.@extract:{"sep":"/","pos":2}
        permission:
          selector: context.request.http.method.@replace:{"old":"GET","new":"read"}.@replace:{"old":"POST","new":"write"}
EOF
```

## ❼ Create the API keys

For Emilia (writer):

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-writer
  labels:
    authorino.kuadrant.io/managed-by: authorino
    app: talker-api
  annotations:
    username: emilia
stringData:
  api_key: IAMEMILIA
EOF
```

For Beatrice (reader):

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-reader
  labels:
    authorino.kuadrant.io/managed-by: authorino
    app: talker-api
  annotations:
    username: beatrice
stringData:
  api_key: IAMBEATRICE
EOF
```

## ❽ Consume the API

As Emilia, send a GET request:

```sh
curl -H 'Authorization: APIKEY IAMEMILIA' \
     -X GET \
     http://talker-api.127.0.0.1.nip.io:8000/posts/1 -i
# HTTP/1.1 200 OK
```

As Emilia, send a POST request:

```sh
curl -H 'Authorization: APIKEY IAMEMILIA' \
     -X POST \
     http://talker-api.127.0.0.1.nip.io:8000/posts/1 -i
# HTTP/1.1 200 OK
```

As Beatrice, send a GET request:

```sh
curl -H 'Authorization: APIKEY IAMBEATRICE' \
     -X GET \
     http://talker-api.127.0.0.1.nip.io:8000/posts/1 -i
# HTTP/1.1 200 OK
```

As Beatrice, send a POST request:

```sh
curl -H 'Authorization: APIKEY IAMBEATRICE' \
     -X POST \
     http://talker-api.127.0.0.1.nip.io:8000/posts/1 -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: PERMISSIONSHIP_NO_PERMISSION;token=GhUKEzE2NzU3MDE3MjAwMDAwMDAwMDA=
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete secret/api-key-1
kubectl delete authconfig/talker-api-protection
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
kubectl delete namespace spicedb
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
