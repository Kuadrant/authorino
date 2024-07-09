# User guide: Kubernetes RBAC for service authorization (SubjectAccessReview API)

Manage permissions in the Kubernetes RBAC and let Authorino to check them in request-time with the authorization system of the cluster.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Authorization → [Kubernetes SubjectAccessReview](../features.md#kubernetes-subjectaccessreview-authorizationkubernetessubjectaccessreview)
  - Identity verification & authentication → [Kubernetes TokenReview](../features.md#kubernetes-tokenreview-authenticationkubernetestokenreview)


  Authorino can delegate authorization decision to the Kubernetes authorization system, allowing permissions to be stored and managed using the Kubernetes Role-Based Access Control (RBAC) for example. The feature is based on the `SubjectAccessReview` API and can be used for `resourceAttributes` (parameters defined in the `AuthConfig`) or `nonResourceAttributes` (inferring HTTP path and verb from the original request).

  Check out as well the user guide about [Authentication with Kubernetes tokens (TokenReview API)](kubernetes-tokenreview.md).

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC) and to create `TokenRequest`s (to consume the protected service from outside the cluster)
- [jq](https://jqlang.github.io/jq/)

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

The `AuthConfig` below sets all Kubernetes service accounts as trusted users of the API, and relies on the Kubernetes RBAC to enforce authorization using Kubernetes SubjectAccessReview API for non-resource endpoints:

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
  - envoy.default.svc.cluster.local
  authentication:
    "service-accounts":
      kubernetesTokenReview:
        audiences: ["https://kubernetes.default.svc.cluster.local"]
  authorization:
    "k8s-rbac":
      kubernetesSubjectAccessReview:
        user:
          selector: auth.identity.user.username
EOF
```

Check out the [spec](../features.md#kubernetes-subjectaccessreview-authorizationkubernetessubjectaccessreview) for the Authorino Kubernetes SubjectAccessReview authorization feature, for resource attributes permission checks where SubjectAccessReviews issued by Authorino are modeled in terms of common attributes of operations on Kubernetes resources (namespace, API group, kind, name, subresource, verb).

## ❻ Create roles associated with endpoints of the API

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


## ❼ Create the `ServiceAccount`s and permissions to consume the API

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

## ❽ Consume the API

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

<details markdown="1">
  <summary>Extra: consume the API as service account <code>api-consumer-2</code> from <i>outside</i> the cluster</summary>

  <br/>

  Obtain a short-lived access token for service account `api-consumer-2`, bound to the `talker-api-greeter` cluster role in the Kubernetes RBAC, using the Kubernetes TokenRequest API:

  ```sh
  export ACCESS_TOKEN=$(echo '{ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": { "expirationSeconds": 600 } }' | kubectl create --raw /api/v1/namespaces/default/serviceaccounts/api-consumer-2/token -f - | jq -r .status.token)
  ```

  Consume the API as `api-consumer-2` from outside the cluster:

  ```sh
  curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api.127.0.0.1.nip.io:8000/hello -i
  # HTTP/1.1 200 OK
  ```

  ```sh
  curl -H "Authorization: Bearer $ACCESS_TOKEN" -X POST http://talker-api.127.0.0.1.nip.io:8000/say/something -i
  # HTTP/1.1 403 Forbidden
  ```
</details>

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
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
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
