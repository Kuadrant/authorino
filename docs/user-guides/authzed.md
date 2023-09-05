# User guide: Integration with Authzed/SpiceDB

Permission requests sent to a Google Zanzibar-based [Authzed/SpiceDB](https://authzed.com) instance, via gRPC.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Authorization → <a href="./../features.md#authzedspicedb-authorizationauthzed">Authzed/SpiceDB</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
    </ul>
  </summary>
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

## 5. Create the permission database

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

Forward local request to the SpiceDB service:

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

## 6. Create the `AuthConfig`

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
  - talker-api-authorino.127.0.0.1.nip.io
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

## 7. Create the API keys

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

## 8. Consume the API

As Emilia, send a GET request:

```sh
curl -H 'Authorization: APIKEY IAMEMILIA' \
     -X GET \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/posts/1 -i
# HTTP/1.1 200 OK
```

As Emilia, send a POST request:

```sh
curl -H 'Authorization: APIKEY IAMEMILIA' \
     -X POST \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/posts/1 -i
# HTTP/1.1 200 OK
```

As Beatrice, send a GET request:

```sh
curl -H 'Authorization: APIKEY IAMBEATRICE' \
     -X GET \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/posts/1 -i
# HTTP/1.1 200 OK
```

As Beatrice, send a POST request:

```sh
curl -H 'Authorization: APIKEY IAMBEATRICE' \
     -X POST \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/posts/1 -i
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
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete namespace spicedb
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
