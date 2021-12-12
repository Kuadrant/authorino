# Getting started

This page covers requirements and instructions to deploy Authorino on a Kubernetes cluster, as well as the steps to declare, apply and try out a protection layer of authentication and authorization over your service, clean-up and complete uninstall.

If you prefer learning with an example, check out our [Hello World](./user-guides/hello-world.md).

- [Requirements](#requirements)
- [Install with the operator](#install-with-the-operator)
- [Protect a service](#protect-a-service)
- [Clean-up](#clean-up)
- [Next steps](#next-steps)

## Requirements

### Platform requirements

These are the plarform requirements to use Authorino:

- [**Kubernetes**](https://kubernetes.io) server (recommended v1.20 or later), with permission to create Kubernetes Custom Resource Definitions (CRDs) (for bootstrapping Authorino and Authorino Operator)

  <details>
    <summary>Alternative: K8s distros and platforms</summary>

    Alternatively to upstream Kubernetes, you should be able use any other Kubernetes distribution or Kubernetes Management Platform (KMP) with support for Kubernetes Custom Resources Definitions (CRD) and custom controllers, such as <a href="https://www.openshift.com">Red Hat OpenShift</a>, <a href="https://www.ibm.com/cloud/kubernetes-service">IBM Cloud Kubernetes Service (IKS)</a>, <a href="http://cloud.google.com/kubernetes-engine">Google Kubernetes Engine (GKE)</a>, <a href="https://aws.amazon.com/eks">Amazon Elastic Kubernetes Service (EKS)</a> and <a href="https://azure.microsoft.com/en-us/services/kubernetes-service">Azure Kubernetes Service (AKS)</a>.
  </details>

- [**Envoy**](https://www.envoyproxy.io) proxy (recommended v1.19 or later), to wire up Upstream services (i.e. the services to be protected with Authorino) and external authorization filter (Authorino) for integrations based on the reverse-proxy architecture - [example](https://github.com/kuadrant/authorino-examples#envoy)

  <details>
    <summary>Alternative: Non-reverse-proxy integration</summary>

    Technically, any client that implements Envoy's <a href="https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz">external authorization</a> gRPC protocol should be compatible with Authorino. For integrations based on the reverse-proxy architecture nevertheless, we strongly recommended that you leverage Envoy along side Authorino.
  </details>

### Feature-specific requirements

Check out the [Features](./features.md) specification for fature-specific requirements. A few examples are:

- For **OpenID Connect**, make sure you have access to an identity provider (IdP) and an authority that can issue ID tokens (JWTs). Check out [Keycloak](https://www.keycloak.org) which can solve both and connect to external identity sources and user federation like LDAP.

- For **Kubernetes authentication** tokens, platform support for the TokenReview and SubjectAccessReview APIs of Kubernetes shall be required. In case you want to be able to requests access tokens for clients running outside the custer, you may also want to check out the requisites for using Kubernetes [TokenRquest API](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#tokenrequest-v1-storage-k8s-io) (GA in v1.20).

- For **User-Managed Access (UMA)** resource data, you will need a UMA-compliant server running as well. This can be an implementation of the UMA protocol by each upstream API itself or (more tipically) an external server that knows about the resources. Again, Keycloak can be a good fit here as well. Just keep in mind that, whatever resource server you choose, changing-state actions commanded in the upstream APIs or other parties will have to be reflected in the resource server. Authorino will not do that for you.

## Install with the operator

### 1. Clone and install the Authorino Operator

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

### 2. Deploy an Authorino instance

Choose either [cluster-wide or namespaced deployment mode](./architecture.md#cluster-wide-vs-namespaced-instances) and whether you want TLS termination enabled for the Authorino endpoints (gRPC and OIDC Discovery), and follow the corresponding instructions below.

The instructions here are for centralized gateway or centralized authorization service architecture. Check out the [Topologies](./architecture.md#topologies) section of the docs for alternatively running Authorino in a sidecar container.

<details>
  <summary><strong>Cluster-wide (with TLS)</strong></summary>

  Create the namespace:
  ```sh
  kubectl create namespace authorino
  ```

  Deploy [cert-manager](https://github.com/jetstack/cert-manager) <small>(skip if you already have certificates and certificate keys created and stored in Kubernetes `Secret`s in the namespace or cert-manager is installed and running in the cluster)</small>:
  ```sh
  kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
  ```

  Create the TLS certificates <small>(skip if you already have certificates and certificate keys created and stored in Kubernetes `Secret`s in the namespace)</small>:
  ```sh
  curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/authorino/g" | kubectl -n authorino apply -f -
  ```

  Deploy Authorino:
  ```sh
  kubectl -n authorino apply -f -<<EOF
  apiVersion: operator.authorino.kuadrant.io/v1beta1
  kind: Authorino
  metadata:
    name: authorino
  spec:
    image: quay.io/3scale/authorino:v0.5.0
    replicas: 1
    clusterWide: true
    listener:
      tls:
        certSecretRef:
          name: authorino-server-cert
    oidcServer:
      tls:
        certSecretRef:
          name: authorino-oidc-server-cert
  EOF
  ```
</details>

<details>
  <summary><strong>Cluster-wide (without TLS)</strong></summary>

  ```sh
  kubectl create namespace authorino
  kubectl -n authorino apply -f -<<EOF
  apiVersion: operator.authorino.kuadrant.io/v1beta1
  kind: Authorino
  metadata:
    name: authorino
  spec:
    image: quay.io/3scale/authorino:v0.5.0
    replicas: 1
    clusterWide: true
    listener:
      tls:
        enabled: false
    oidcServer:
      tls:
        enabled: false
  EOF
  ```
</details>

<details>
  <summary><strong>Namespaced (with TLS)</strong></summary>

  Create the namespace:
  ```sh
  kubectl create namespace myapp
  ```

  Deploy [cert-manager](https://github.com/jetstack/cert-manager) <small>(skip if you already have certificates and certificate keys created and stored in Kubernetes `Secret`s in the namespace or cert-manager is installed and running in the cluster)</small>:
  ```sh
  kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
  ```

  Create the TLS certificates <small>(skip if you already have certificates and certificate keys created and stored in Kubernetes `Secret`s in the namespace)</small>:
  ```sh
  curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/myapp/g" | kubectl -n myapp apply -f -
  ```

  Deploy Authorino:
  ```sh
  kubectl -n myapp apply -f -<<EOF
  apiVersion: operator.authorino.kuadrant.io/v1beta1
  kind: Authorino
  metadata:
    name: authorino
  spec:
    image: quay.io/3scale/authorino:v0.5.0
    replicas: 1
    clusterWide: false
    listener:
      tls:
        certSecretRef:
          name: authorino-server-cert
    oidcServer:
      tls:
        certSecretRef:
          name: authorino-oidc-server-cert
  EOF
  ```
</details>

<details>
  <summary><strong>Namespaced (without TLS)</strong></summary>

  ```sh
  kubectl create namespace myapp
  kubectl -n myapp apply -f -<<EOF
  apiVersion: operator.authorino.kuadrant.io/v1beta1
  kind: Authorino
  metadata:
    name: authorino
  spec:
    image: quay.io/3scale/authorino:v0.5.0
    replicas: 1
    clusterWide: false
    listener:
      tls:
        enabled: false
    oidcServer:
      tls:
        enabled: false
  EOF
  ```
</details>

## Protect a service

The most common integration to protect resources with Authorino is by putting the _upstream_ service that serves the resources (i.e. the _resource server_ to be protected) behind a reverse-proxy enabled with an authorization filter. To do that, start by having you **upstream service deployed and running** in the Kubernetes server. Then, setup [Envoy](https://www.envoyproxy.io) and create an Authorino `AuthConfig` for your service.

### 1. Setup Envoy

To configure Envoy for proxying requests intended to the upstream service, authorizing with Authorino, setup an Envoy configuration that enables Envoy's [external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) filter. Store the configuration in a `ConfigMap`.

These are the important bits in the Envoy configuration to activate Authorino:

```yaml
static_resources:
  listeners:
  - address: {…} # TCP socket address and port of the proxy
    filter_chains:
    - filters:
      - name: envoy.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          route_config: {…} # routing configs - virtual host domain and endpoint matching patterns and corresponding upstream services to redirect the traffic
          http_filters:
          - name: envoy.filters.http.ext_authz # the external authorization filter
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              transport_api_version: V3
              failure_mode_allow: false # ensures only authenticated and authorized traffic goes through
              grpc_service:
                envoy_grpc:
                  cluster_name: external_auth
                timeout: 1s
  clusters:
  - name: external_auth
    connect_timeout: 0.25s
    type: strict_dns
    lb_policy: round_robin
    http2_protocol_options: {}
    load_assignment:
      cluster_name: external_auth
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: authorino-authorino-authorization # name of the Authorino service deployed – it can be the fully qualified name with `.<namespace>.svc.cluster.local` suffix (e.g. `authorino-authorino-authorization.myapp.svc.cluster.local`)
                port_value: 50051
    transport_socket: # in case TLS termination is enabled in Authorino; omit it otherwise
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          validation_context:
            trusted_ca:
              filename: /etc/ssl/certs/authorino-ca-cert.crt
```

For a complete Envoy `ConfigMap` containing an upstream API protected with Authorino, with TLS enabled and option for rate limiting with [Limitador](https://github.com/kuadrant/limitador), plus a webapp served with under the same domain of the protected API, check out this [example](https://github.com/kuadrant/authorino-examples/blob/main/envoy/overlays/tls/configmap.yaml).

After creating the `ConfigMap` with the Envoy configuration, create an Envoy `Deployment` and `Service`. E.g.:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envoy
  labels:
    app: envoy
spec:
  selector:
    matchLabels:
      app: envoy
  template:
    metadata:
      labels:
        app: envoy
    spec:
      containers:
        - name: envoy
          image: envoyproxy/envoy:v1.19-latest
          command: ["/usr/local/bin/envoy"]
          args:
            - --config-path /usr/local/etc/envoy/envoy.yaml
            - --service-cluster front-proxy
            - --log-level info
            - --component-log-level filter:trace,http:debug,router:debug
          ports:
            - name: web
              containerPort: 8000 # matches the adddress of the listener in the envoy config
          volumeMounts:
            - name: config
              mountPath: /usr/local/etc/envoy
              readOnly: true
            - name: authorino-ca-cert # in case TLS termination is enabled in Authorino; omit it otherwise
              subPath: ca.crt
              mountPath: /etc/ssl/certs/authorino-ca-cert.crt
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: envoy
            items:
              - key: envoy.yaml
                path: envoy.yaml
        - name: authorino-ca-cert # in case TLS termination is enabled in Authorino; omit it otherwise
          secret:
            defaultMode: 420
            secretName: authorino-ca-cert
  replicas: 1
EOF
```

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: v1
kind: Service
metadata:
  name: envoy
spec:
  selector:
    app: envoy
  ports:
    - name: web
      port: 8000
      protocol: TCP
EOF
```

### 2. Apply an `AuthConfig`

Check out the [docs](./README.md) for a full description of Authorino's [`AuthConfig`](./architecture.md#the-authorino-authconfig-custom-resource-definition-crd) Custom Resource Definition (CRD) and its [features](./features.md).

For examples based on specific use-cases, check out the [User guides](./user-guides.md).

For a OpenID Connect/JWT verification authentication and one JWT claim authorization check, a typical `AuthConfig` custom resource looks like the following:

```yaml
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: my-api-protection
spec:
  hosts: # any hosts that resolve to the envoy service and envoy routing config where the external authorization filter is enabled
    - my-api.io # north-south traffic through a Kubernetes `Ingress` or OpenShift `Route`
    - my-api.myapp.svc.cluster.local # east-west traffic (between applications within the cluster)
  identity:
    - name: idp-users
      oidc:
        endpoint: https://my-idp.com/auth/realm
  authorization:
    - name: check-claim
      json:
        rules:
          - selector: auth.identity.group
            operator: eq
            value: allowed-users
EOF
```

After applying the `AuthConfig`, consumers of the protected service should be able to start sending requests.

## Clean-up

### 1. Remove protection

Delete the `AuthConfig`:

```sh
kubectl -n myapp delete authconfig/my-api-protection
```

Decommission the Authorino instance:

```sh
kubectl -n myapp delete authorino/authorino
```

### 2. Uninstall

To completely remove Authorino CRDs, run from the Authorino Operator directory:

```sh
make uninstall
```

## Next steps

1. Read the [docs](./README.md). The [Architecture](./architecture.md) page and the [Features](./features.md) page are good starting points to learn more about how Authorino works and its functionalities.
2. Check out the [User guides](./user-guides.md) for several examples of `AuthConfig`s based on specific use-cases
