# User guide: Kubernetes RBAC for service authorization (SubjectAccessReview API)

Manage permissions in the Kubernetes RBAC and let Authorino to check them in request-time with the authorization system of the cluster.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Authorization → <a href="./../features.md#kubernetes-subjectaccessreview-authorizationkubernetes">Kubernetes SubjectAccessReview</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#kubernetes-tokenreview-identitykubernetes">Kubernetes TokenReview</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#extra-identity-extension-extendedproperties">Identity extension</a></li>
    </ul>
  </summary>

  Authorino can delegate authorization decision to the Kubernetes authorization system, allowing permissions to be stored and managed using the Kubernetes Role-Based Access Control (RBAC) for example. The feature is based on the `SubjectAccessReview` API and can be used for `resourceAttributes` or `nonResourceAttributes` (the latter inferring HTTP verb and method from the original request).

  Check out as well the user guides about [Authentication with Kubernetes tokens (TokenReview API)](./kubernetes-tokenreview.md), [Authentication with API keys](./api-key-authentication.md) and [Token normalization](./token-normalization.md).

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

The `AuthConfig` below defines:
- 2 sets of identities trusted to access the API:
  - users that authenticate with API keys (**`api-key-users`**), and
  - service accounts that authenticate with Kubernetes service account tokens (**`service-accounts`**);
- 2 authorization policies based on Kubernetes SubjectAccessReview:
  - resource access reviews when the requested endpoint matches `/resources(/\w+)?` (**`resource-endpoints`**), and
  - non-resource access reviews when the requested endpoint does not match `/resources(/\w+)?` (**`non-resource-endpoints`**)

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
  - name: service-accounts
    kubernetes:
      audiences:
      - talker-api
    extendedProperties:
    - name: username
      valueFrom:
        authJSON: auth.identity.sub
  - name: api-key-users
    apiKey:
      labelSelectors:
        audiences: talker-api
    extendedProperties:
    - name: username
      valueFrom:
        authJSON: auth.identity.metadata.annotations.username
    credentials:
      in: authorization_header
      keySelector: APIKEY
  authorization:
  - name: non-resource-endpoints
    kubernetes:
      conditions:
      - selector: context.request.http.path.@extract:{"sep":"/","pos":1}
        operator: neq
        value: resources
      user:
        valueFrom:
          authJSON: auth.identity.username
  - name: resource-endpoints
    kubernetes:
      conditions:
      - selector: context.request.http.path
        operator: matches
        value: ^/resources(/\w+)?
      user:
        valueFrom:
          authJSON: auth.identity.username
      resourceAttributes:
        namespace:
          value: authorino
        group:
          value: talker-api.authorino.3scale.net
        resource:
          value: resources
        name:
          valueFrom:
            authJSON: context.request.http.path.@extract:{"sep":"/","pos":2}
        verb:
          valueFrom:
            authJSON: context.request.http.method.@case:lower
EOF
```

## 7. Create roles associated with endpoints of the API

Because the authorization policy `non-resource-endpoints`, configured in the `AuthConfig` in the previous step, is for non-resource access review requests, the corresponding roles and role bindings have to be defined at cluster scope, whereas the roles and role bindings for the `resource-endpoints` policy can be scoped to the namespace.

Create a `talker-api-greeter` role whose users and service accounts bound to this role can consume the non-resource endpoints `POST /hello` and `POST /hey` of the API:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: talker-api-greeter
rules:
- nonResourceURLs: ["/hello"]
  verbs: ["post"]
- nonResourceURLs: ["/hey"]
  verbs: ["post"]
EOF
```

Create a `talker-api-speaker` role whose users and service accounts bound to this role can consume the non-resource endpoints `POST /say/*` of the API:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: talker-api-speaker
rules:
- nonResourceURLs: ["/say/*"]
  verbs: ["post"]
EOF
```

Create a `talker-api-resource-reader` role whose users and service accounts bound to this role can consume the resource endpoints `GET /resources[/*]` of the API:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: talker-api-resource-reader
rules:
- apiGroups: ["talker-api.authorino.3scale.net"]
  resources: ["resources"]
  verbs: ["get"]
EOF
```


## 8. Create a few API keys and `ServiceAccount` and permissions

Create service accounts `api-consumer-1` and `api-consumer-2`:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-consumer-1
EOF
```

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-consumer-2
EOF
```

Create an API key `api-key-1` for user `john`:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.3scale.net/managed-by: authorino
    audiences: talker-api
  annotations:
    username: john
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

Create an API key `api-key-2` for user `jane`:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-2
  labels:
    authorino.3scale.net/managed-by: authorino
    audiences: talker-api
  annotations:
    username: jane
stringData:
  api_key: Vb8Ymt1Y2hWvaKcAcElau81ia2CsAYUn
type: Opaque
EOF
```

Bind all users and service accounts to the `talker-api-greeter` role:

```sh
kubectl -n authorino apply -f -<<EOF
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
  namespace: authorino
- kind: ServiceAccount
  name: api-consumer-2
  namespace: authorino
- kind: User
  name: john
- kind: User
  name: jane
EOF
```

Bind service account `api-consumer-1` and user `john` to the `talker-api-speaker` role:

```sh
kubectl -n authorino apply -f -<<EOF
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
  namespace: authorino
- kind: User
  name: john
EOF
```

Bind service account `api-consumer-1` and user `john` to the `talker-api-resource-reader` role:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: talker-api-resource-reader-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: talker-api-resource-reader
subjects:
- kind: ServiceAccount
  name: api-consumer-1
  namespace: authorino
- kind: User
  name: john
  namespace: authorino
EOF
```

## 9. Consume the API

Consume the API as `john`, who is bound to the `talker-api-greeter`, `talker-api-speaker` and `talker-api-resource-reader` roles in the Kubernetes RBAC:

```sh
curl -H "Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -H "Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/say/i-love-you
# HTTP/1.1 200 OK
```

```sh
curl -H "Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" http://talker-api-authorino.127.0.0.1.nip.io:8000/resources
# HTTP/1.1 200 OK
```

Consume the API as `jane`, who is bound to the `talker-api-greeter` role in the Kubernetes RBAC:

```sh
curl -H "Authorization: APIKEY Vb8Ymt1Y2hWvaKcAcElau81ia2CsAYUn" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/hey
# HTTP/1.1 200 OK
```

```sh
curl -H "Authorization: APIKEY Vb8Ymt1Y2hWvaKcAcElau81ia2CsAYUn" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/say/something -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Not authorized: unknown reason
```

```sh
curl -H "Authorization: APIKEY Vb8Ymt1Y2hWvaKcAcElau81ia2CsAYUn" http://talker-api-authorino.127.0.0.1.nip.io:8000/resources -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Not authorized: unknown reason
```

To consume the API as a service account sending requests from outside the cluster, get the Kubernetes API base endpoint and current Kubernetes user, and save the user's TLS certificate and TLS key to file:

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

Consume the API as `api-consumer-1`, which is bound to the `talker-api-greeter`, `talker-api-speaker` and `talker-api-resource-reader` roles in the Kubernetes RBAC:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/say/happy-to-be-here
# HTTP/1.1 200 OK
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/resources/123
# HTTP/1.1 200 OK
```

Use the Kubernetes user's client TLS certificate to obtain a short-lived access token for the `api-consumer-2` `ServiceAccount`:

```sh
export ACCESS_TOKEN=$(curl -k -X "POST" "$KUBERNETES_API/api/v1/namespaces/authorino/serviceaccounts/api-consumer-2/token" \
     --cert /tmp/kind-cluster-user-cert.pem --key /tmp/kind-cluster-user-cert.key \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d $'{ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": { "audiences": ["talker-api"], "expirationSeconds": 600 } }' | jq -r '.status.token')
```

Consume the API as `api-consumer-2`, which is bound to the `talker-api-greeter` role in the Kubernetes RBAC:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/hey
# HTTP/1.1 200 OK
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api-authorino.127.0.0.1.nip.io:8000/say/something -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Not authorized: unknown reason
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/resources/123 -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Not authorized: unknown reason
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
