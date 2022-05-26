# User guide: Kubernetes RBAC for service authorization (SubjectAccessReview API)

Manage permissions in the Kubernetes RBAC and let Authorino to check them in request-time with the authorization system of the cluster.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Authorization → <a href="./../features.md#kubernetes-subjectaccessreview-authorizationkubernetes">Kubernetes SubjectAccessReview</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#kubernetes-tokenreview-identitykubernetes">Kubernetes TokenReview</a></li>
    </ul>
  </summary>

  Authorino can delegate authorization decision to the Kubernetes authorization system, allowing permissions to be stored and managed using the Kubernetes Role-Based Access Control (RBAC) for example. The feature is based on the `SubjectAccessReview` API and can be used for `resourceAttributes` (parameters defined in the `AuthConfig`) or `nonResourceAttributes` (inferring HTTP path and verb from the original request).

  Check out as well the user guide about [Authentication with Kubernetes tokens (TokenReview API)](./kubernetes-tokenreview.md).

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

The command above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `namespaced` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 4. Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#1-setup-envoy) page. For a simpler and straighforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl port-forward deployment/envoy 8000:8000 &
```

## 5. Create the `AuthConfig`

The `AuthConfig` below sets all Kubernetes service accounts as trusted users of the API, and relies on the Kubernetes RBAC to enforce authorization using Kubernetes SubjectAccessReview API for non-resource endpoints:

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
  - name: service-accounts
    kubernetes:
      audiences: ["https://kubernetes.default.svc.cluster.local"]
  authorization:
  - name: k8s-rbac
    kubernetes:
      user:
        valueFrom: { authJSON: auth.identity.sub }
EOF
```

Check out the [spec](./../features.md#kubernetes-subjectaccessreview-authorizationkubernetes) for the Authorino Kubernetes SubjectAccessReview authorization feature, for resource attributes permission checks where SubjectAccessReviews issued by Authorino are modeled in terms of common attributes of operations on Kubernetes resources (namespace, API group, kind, name, subresource, verb).

## 6. Create roles associated with endpoints of the API

Because the `k8s-rbac` policy defined in the `AuthConfig` in the previous step is for non-resource access review requests, the corresponding roles and role bindings have to be defined at cluster scope.

Create a `talker-api-greeter` role whose users and service accounts bound to this role can consume the non-resource endpoints `POST /hello` and `POST /hi` of the API:

```sh
kubectl apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: talker-api-greeter
rules:
- nonResourceURLs: ["/hello"]
  verbs: ["post"]
- nonResourceURLs: ["/hi"]
  verbs: ["post"]
EOF
```

Create a `talker-api-speaker` role whose users and service accounts bound to this role can consume the non-resource endpoints `POST /say/*` of the API:

```sh
kubectl apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: talker-api-speaker
rules:
- nonResourceURLs: ["/say/*"]
  verbs: ["post"]
EOF
```


## 7. Create the `ServiceAccount`s and permissions to consume the API

Create service accounts `api-consumer-1` and `api-consumer-2`:

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-consumer-1
EOF
```

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-consumer-2
EOF
```

Bind both service accounts to the `talker-api-greeter` role:

```sh
kubectl apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: talker-api-greeter-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: talker-api-greeter
subjects:
- kind: ServiceAccount
  name: api-consumer-1
  namespace: default
- kind: ServiceAccount
  name: api-consumer-2
  namespace: default
EOF
```

Bind service account `api-consumer-1` to the `talker-api-speaker` role:

```sh
kubectl apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: talker-api-speaker-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: talker-api-speaker
subjects:
- kind: ServiceAccount
  name: api-consumer-1
  namespace: default
EOF
```


## 8. Consume the API

Run a pod that consumes one of the greeting endpoints of the API from inside the cluster, as service account `api-consumer-1`, bound to the `talker-api-greeter` and `talker-api-speaker` cluster roles in the Kubernetes RBAC:

```sh
kubectl run greeter --attach --rm --restart=Never -q --image=quay.io/kuadrant/authorino-examples:api-consumer --overrides='{
  "apiVersion": "v1",
  "spec": {
    "containers": [{
      "name": "api-consumer", "image": "quay.io/kuadrant/authorino-examples:api-consumer", "command": ["./run"],
      "args":["--endpoint=http://envoy.default.svc.cluster.local:8000/hi","--method=POST","--interval=0","--token-path=/var/run/secrets/tokens/api-token"],
      "volumeMounts": [{"mountPath": "/var/run/secrets/tokens","name": "access-token"}]
    }],
    "serviceAccountName": "api-consumer-1",
    "volumes": [{"name": "access-token","projected": {"sources": [{"serviceAccountToken": {"path": "api-token","expirationSeconds": 7200}}]}}]
  }
}' -- sh
# Sending...
# 200
```

Run a pod that sends a `POST` request to `/say/blah` from within the cluster, as service account `api-consumer-1`:

```sh
kubectl run speaker --attach --rm --restart=Never -q --image=quay.io/kuadrant/authorino-examples:api-consumer --overrides='{
  "apiVersion": "v1",
  "spec": {
    "containers": [{
      "name": "api-consumer", "image": "quay.io/kuadrant/authorino-examples:api-consumer", "command": ["./run"],
      "args":["--endpoint=http://envoy.default.svc.cluster.local:8000/say/blah","--method=POST","--interval=0","--token-path=/var/run/secrets/tokens/api-token"],
      "volumeMounts": [{"mountPath": "/var/run/secrets/tokens","name": "access-token"}]
    }],
    "serviceAccountName": "api-consumer-1",
    "volumes": [{"name": "access-token","projected": {"sources": [{"serviceAccountToken": {"path": "api-token","expirationSeconds": 7200}}]}}]
  }
}' -- sh
# Sending...
# 200
```

Run a pod that sends a `POST` request to `/say/blah` from within the cluster, as service account `api-consumer-2`, bound only to the `talker-api-greeter` cluster role in the Kubernetes RBAC:

```sh
kubectl run speaker --attach --rm --restart=Never -q --image=quay.io/kuadrant/authorino-examples:api-consumer --overrides='{
  "apiVersion": "v1",
  "spec": {
    "containers": [{
      "name": "api-consumer", "image": "quay.io/kuadrant/authorino-examples:api-consumer", "command": ["./run"],
      "args":["--endpoint=http://envoy.default.svc.cluster.local:8000/say/blah","--method=POST","--interval=0","--token-path=/var/run/secrets/tokens/api-token"],
      "volumeMounts": [{"mountPath": "/var/run/secrets/tokens","name": "access-token"}]
    }],
    "serviceAccountName": "api-consumer-2",
    "volumes": [{"name": "access-token","projected": {"sources": [{"serviceAccountToken": {"path": "api-token","expirationSeconds": 7200}}]}}]
  }
}' -- sh
# Sending...
# 403
```

<details>
  <summary>Extra: consume the API as service account <code>api-consumer-2</code> from <i>outside</i> the cluster</summary>

  <br/>

  Obtain a short-lived access token for service account `api-consumer-2`, bound to the `talker-api-greeter` cluster role in the Kubernetes RBAC, using the Kubernetes TokenRequest API:

  ```sh
  export ACCESS_TOKEN=$(echo '{ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": { "expirationSeconds": 600 } }' | kubectl create --raw /api/v1/namespaces/default/serviceaccounts/api-consumer-2/token -f - | jq -r .status.token)
  ```

  Consume the API as `api-consumer-2` from outside the cluster:

  ```sh
  curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/hello -i
  # HTTP/1.1 200 OK
  ```

  ```sh
  curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/say/something -i
  # HTTP/1.1 403 Forbidden
  ```
</details>

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-trial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete serviceaccount/api-consumer-1
kubectl delete serviceaccount/api-consumer-2
kubectl delete clusterrolebinding/talker-api-greeter-rolebinding
kubectl delete clusterrolebinding/talker-api-speaker-rolebinding
kubectl delete clusterrole/talker-api-greeter
kubectl delete clusterrole/talker-api-speaker
kubectl delete authconfig/talker-api-protection
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
