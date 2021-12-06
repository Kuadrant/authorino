# User guide: Reducing the operational space

By default, Authorino will watch events related to all `AuthConfig` custom resources in the reconciliation space (namespace or entire cluster). Instances can be configured though to only watch a subset of the resources, thus allowing such as:
- to reduce noise and lower memory usage inside instances meant for restricted scope (e.g. Authorino deployed as a dedicated sidecar to protect only one host);
- sharding auth config data across multiple instances;
- multiple environments (e.g. staging, production) inside of a same cluster/namespace;
- providing managed instances of Authorino that all watch CRs cluster-wide, yet dedicated to organizations allowed to create and operate their own `AuthConfig`s across multiple namespaces.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li><a href="./../architecture.md#sharding">Sharding</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
    </ul>
  </summary>

  Check out as well the user guide about [Authentication with API keys](./api-key-authentication.md).

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-trial
```

## 1. Install the Authorino Operator

```sh
git clone https://github.com/kuadrant/authorino-operator && cd authorino-operator
kubectl create namespace authorino-operator && make install deploy
```

## 2. Create a namespace for the Authorino instances

```sh
kubectl create namespace authorino
```

## 3. Deploy a couple instances of Authorino

Deploy an instance of Authorino dedicated to `AuthConfig`s and API key `Secrets` labeled with `authorino/environment=staging`:

```sh
kubectl -n authorino apply -f -<<EOF
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
kubectl -n authorino apply -f -<<EOF
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

The commands above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `cluster-wide` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 7. Create a namespace for user resources

```sh
kubectl create namespace myapp
```

## 8. Create `AuthConfig`s and API key `Secret`s for both instances

### Create resources for `authorino-staging`

Create an `AuthConfig`:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: auth-config-1
  labels:
    authorino/environment: staging
spec:
  hosts:
  - my-host.staging.io
  identity:
  - name: api-key
    apiKey:
      labelSelectors:
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

Verify in the logs that only the `authorino-staging` instance adds the resources to the cache:

```sh
kubectl -n authorino logs $(kubectl -n authorino get pods -l authorino-resource=authorino-staging -o name)
# {"level":"info","ts":1638382989.8327162,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"myapp/auth-config-1"}
# {"level":"info","ts":1638382989.837424,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig/status":"myapp/auth-config-1"}
# {"level":"info","ts":1638383144.9486837,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"myapp/api-key-1"}
```

### Create resources for `authorino-production`

Create an `AuthConfig`:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: auth-config-2
  labels:
    authorino/environment: production
spec:
  hosts:
  - my-host.io
  identity:
  - name: api-key
    apiKey:
      labelSelectors:
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

Verify in the logs that only the `authorino-production` instance adds the resources to the cache:

```sh
kubectl -n authorino logs $(kubectl -n authorino get pods -l authorino-resource=authorino-production -o name)
# {"level":"info","ts":1638383423.86086,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig/status":"myapp/auth-config-2"}
# {"level":"info","ts":1638383423.8608105,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"myapp/auth-config-2"}
# {"level":"info","ts":1638383460.3515081,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"myapp/api-key-2"}
```

## 9. Remove a resource from scope

```sh
kubectl -n myapp label authconfig/auth-config-2 disabled=true
# authconfig.authorino.3scale.net/auth-config-2 labeled
```

Verify in the logs that only the `authorino-production` instance adds the resources to the cache:

```sh
kubectl -n authorino logs $(kubectl -n authorino get pods -l authorino-resource=authorino-production -o name)
# {"level":"info","ts":1638383515.6428752,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"myapp/auth-config-2"}
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind only to test this user guide, delete it by running:

```sh
kind delete cluster --name authorino-trial
```

Otherwise, delete the namespaces created in step 1 and 2:

```sh
kubectl -n authorino namespace myapp
kubectl -n authorino namespace authorino
kubectl -n authorino namespace authorino-operator
```

To uninstall the Authorino and Authorino Operator manifests, run from the Authorino Operator directory:

```sh
make uninstall
```
