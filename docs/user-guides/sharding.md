# User guide: Reducing the operational space

By default, Authorino will watch events related to all `AuthConfig` custom resources in the reconciliation space (namespace or entire cluster). Instances can be configured though to only watch a subset of the resources, thus allowing such as:

- to reduce noise and lower memory usage inside instances meant for restricted scope (e.g. Authorino deployed as a dedicated sidecar to protect only one host);
- sharding auth config data across multiple instances;
- multiple environments (e.g. staging, production) inside of a same cluster/namespace;
- providing managed instances of Authorino that all watch CRs cluster-wide, yet dedicated to organizations allowed to create and operate their own `AuthConfig`s across multiple namespaces.

<table>
  <tbody>
    <tr>
      <td>
        <b>⚠️ <i>Important:</i></b>
        This feature may not be available to users of Authorino via <a href="https://kuadrant.io">Kuadrant</a>.
      </td>
    </tr>
  </tbody>
</table>

<details markdown="1">
  <summary markdown="1">Authorino capabilities featured in this guide</summary>

  - [Sharding](https://docs.kuadrant.io/authorino/docs/architecture#sharding)
  - Identity verification & authentication →[API key](https://docs.kuadrant.io/authorino/docs/features#api-key-authenticationapikey)

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

## ❶ Install the Authorino Operator (cluster admin required)

The following command will install the [Authorino Operator](http://github.com/kuadrant/authorino-operator) in the Kubernetes cluster. The operator manages instances of the Authorino authorization service.

```sh
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
```

## ❷ Deploy instances of Authorino

Deploy an instance of Authorino dedicated to `AuthConfig`s and API key `Secrets` labeled with `authorino/environment=staging`:

```sh
kubectl apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino-staging
spec:
  clusterWide: true
  authConfigLabelSelectors: authorino/environment=staging
  secretLabelSelectors: authorino/environment=staging
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
EOF
```

Deploy an instance of Authorino dedicated to `AuthConfig`s and API key `Secrets` labeled with `authorino/environment=production`, ans NOT labeled `disabled`:

```sh
kubectl apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino-production
spec:
  clusterWide: true
  authConfigLabelSelectors: authorino/environment=production,!disabled
  secretLabelSelectors: authorino/environment=production,!disabled
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
EOF
```

The commands above will both request instances of Authorino that watch for `AuthConfig` resources cluster-wide[^1], with TLS disabled[^2].

[^1]: `cluster-wide` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^2]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.

## ❸ Create a namespace for user resources

```sh
kubectl create namespace myapp
```

## ❹ Create `AuthConfig`s and API key `Secret`s for both instances

### Create resources for `authorino-staging`

Create an `AuthConfig`:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: auth-config-1
  labels:
    authorino/environment: staging
spec:
  hosts:
  - my-host.staging.io
  authentication:
    "api-key":
      apiKey:
        selector:
          matchLabels:
            authorino/api-key: "true"
            authorino/environment: staging
EOF
```

Create an API key `Secret`:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino/api-key: "true"
    authorino/environment: staging
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

Verify in the logs that only the `authorino-staging` instance adds the resources to the index:

```sh
kubectl logs $(kubectl get pods -l authorino-resource=authorino-staging -o name)
# {"level":"info","ts":1638382989.8327162,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"myapp/auth-config-1"}
# {"level":"info","ts":1638382989.837424,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig/status":"myapp/auth-config-1"}
# {"level":"info","ts":1638383144.9486837,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"myapp/api-key-1"}
```

### Create resources for `authorino-production`

Create an `AuthConfig`:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: auth-config-2
  labels:
    authorino/environment: production
spec:
  hosts:
  - my-host.io
  authentication:
    "api-key":
      apiKey:
        selector:
          matchLabels:
            authorino/api-key: "true"
            authorino/environment: production
EOF
```

Create an API key `Secret`:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-2
  labels:
    authorino/api-key: "true"
    authorino/environment: production
stringData:
  api_key: MUWdeBte7AbSWxl6CcvYNJ+3yEIm5CaL
type: Opaque
EOF
```

Verify in the logs that only the `authorino-production` instance adds the resources to the index:

```sh
kubectl logs $(kubectl get pods -l authorino-resource=authorino-production -o name)
# {"level":"info","ts":1638383423.86086,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig/status":"myapp/auth-config-2"}
# {"level":"info","ts":1638383423.8608105,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"myapp/auth-config-2"}
# {"level":"info","ts":1638383460.3515081,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"myapp/api-key-2"}
```

## ❺ Remove a resource from scope

```sh
kubectl -n myapp label authconfig/auth-config-2 disabled=true
# authconfig.authorino.kuadrant.io/auth-config-2 labeled
```

Verify in the logs that the `authorino-production` instance removes the authconfig from the index:

```sh
kubectl logs $(kubectl get pods -l authorino-resource=authorino-production -o name)
# {"level":"info","ts":1638383515.6428752,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource de-indexed","authconfig":"myapp/auth-config-2"}
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete authorino/authorino-staging
kubectl delete authorino/authorino-production
kubectl delete namespace myapp
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
