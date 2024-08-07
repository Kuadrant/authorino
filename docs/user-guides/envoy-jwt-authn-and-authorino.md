# User guide: Mixing Envoy built-in filter for auth and Authorino

Have JWT validation handled by Envoy beforehand and the JWT payload injected into the request to Authorino, to be used in custom authorization policies defined in a AuthConfig.

In this user guide, we will set up Envoy and Authorino to protect a service called the _Talker API_ service, with JWT authentication handled in Envoy and a more complex authorization policy enforced in Authorino.

The policy defines a geo-fence by which only requests originated in Great Britain (country code: GB) will be accepted, unless the user is bound to a role called 'admin' in the auth server, in which case no geofence is enforced.

All requests to the Talker API will be authenticated in Envoy. However, requests to `/global` will **not** trigger the external authorization.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Identity verification & authentication → [Plain](../features.md#plain-authenticationplain)
  - External auth metadata → [HTTP GET/GET-by-POST](../features.md#http-getget-by-post-metadatahttp)
  - Authorization → [Pattern-matching authorization](../features.md#pattern-matching-authorization-authorizationpatternmatching)
  - Dynamic response → [Custom denial status](../features.md#custom-denial-status-responseunauthenticated-and-responseunauthorized)

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)
- Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq), to extract parts of JSON responses

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

Deploy the identity provider and authentication server by executing the command below. For the examples in this guide, we are going to use a Keycloak server preloaded with all required realm settings.

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
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

The following command deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Talker API behind the reverse-proxy, with external authorization enabled with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app: authorino
  name: envoy
data:
  envoy.yaml: |
    static_resources:
      clusters:
      - name: talker-api
        connect_timeout: 0.25s
        type: strict_dns
        lb_policy: round_robin
        load_assignment:
          cluster_name: talker-api
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: talker-api
                    port_value: 3000
      - name: keycloak
        connect_timeout: 0.25s
        type: logical_dns
        lb_policy: round_robin
        load_assignment:
          cluster_name: keycloak
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: keycloak.keycloak.svc.cluster.local
                    port_value: 8080
      - name: authorino
        connect_timeout: 0.25s
        type: strict_dns
        lb_policy: round_robin
        http2_protocol_options: {}
        load_assignment:
          cluster_name: authorino
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: authorino-authorino-authorization
                    port_value: 50051
      listeners:
      - address:
          socket_address:
            address: 0.0.0.0
            port_value: 8000
        filter_chains:
        - filters:
          - name: envoy.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: local
              route_config:
                name: local_route
                virtual_hosts:
                - name: local_service
                  domains: ['*']
                  routes:
                  - match: { path_separated_prefix: /global }
                    route: { cluster: talker-api }
                    typed_per_filter_config:
                      envoy.filters.http.ext_authz:
                        "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
                        disabled: true
                  - match: { prefix: / }
                    route: { cluster: talker-api }
              http_filters:
              - name: envoy.filters.http.jwt_authn
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                  providers:
                    keycloak:
                      issuer: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
                      remote_jwks:
                        http_uri:
                          uri: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/certs
                          cluster: keycloak
                          timeout: 5s
                        cache_duration:
                          seconds: 300
                      payload_in_metadata: verified_jwt
                  rules:
                  - match: { prefix: / }
                    requires: { provider_name: keycloak }
              - name: envoy.filters.http.ext_authz
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                  transport_api_version: V3
                  failure_mode_allow: false
                  metadata_context_namespaces:
                  - envoy.filters.http.jwt_authn
                  grpc_service:
                    envoy_grpc:
                      cluster_name: authorino
                    timeout: 1s
              - name: envoy.filters.http.router
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              use_remote_address: true
    admin:
      access_log_path: "/tmp/admin_access.log"
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8001
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: authorino
    svc: envoy
  name: envoy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: authorino
      svc: envoy
  template:
    metadata:
      labels:
        app: authorino
        svc: envoy
    spec:
      containers:
      - args:
        - --config-path /usr/local/etc/envoy/envoy.yaml
        - --service-cluster front-proxy
        - --log-level info
        - --component-log-level filter:trace,http:debug,router:debug
        command:
        - /usr/local/bin/envoy
        image: envoyproxy/envoy:v1.22-latest
        name: envoy
        ports:
        - containerPort: 8000
          name: web
        - containerPort: 8001
          name: admin
        volumeMounts:
        - mountPath: /usr/local/etc/envoy
          name: config
          readOnly: true
      volumes:
      - configMap:
          items:
          - key: envoy.yaml
            path: envoy.yaml
          name: envoy
        name: config
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: authorino
  name: envoy
spec:
  ports:
  - name: web
    port: 8000
    protocol: TCP
  selector:
    app: authorino
    svc: envoy
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-wildcard-host
spec:
  rules:
  - host: talker-api.127.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: envoy
            port:
              number: 8000
        path: /
        pathType: Prefix
EOF
```

The command above creates an `Ingress` with host name `talker-api.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8000 to the Envoy service running inside the cluster:

```sh
kubectl port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
```

## ❺ Deploy the IP Location service

The **IP Location service** is a simple service that resolves an IPv4 address into geo location info.

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-examples/main/ip-location/ip-location-deploy.yaml
```

## ❻ Create an `AuthConfig`

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced:

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
    "jwt":
      plain:
        selector: context.metadata_context.filter_metadata.envoy\.filters\.http\.jwt_authn|verified_jwt
  metadata:
    "geoinfo":
      http:
        url: 'http://ip-location.default.svc.cluster.local:3000/{context.request.http.headers.x-forwarded-for.@extract:{"sep":","}}'
        headers:
          "Accept":
            value: application/json
      cache:
        key:
          selector: "context.request.http.headers.x-forwarded-for.@extract:{\"sep\":\",\"}"
  authorization:
    "geofence":
      when:
      - selector: auth.identity.realm_access.roles
        operator: excl
        value: admin
      patternMatching:
        patterns:
        - selector: auth.metadata.geoinfo.country_iso_code
          operator: eq
          value: "GB"
  response:
    unauthorized:
      message:
        selector: "The requested resource is not available in {auth.metadata.geoinfo.country_name}"
EOF
```

## ❼ Obtain a token and consume the API

### Obtain an access token and consume the API as John (member)

Obtain an access token with the Keycloak server for John:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user John, a non-admin (member) user:

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' -d 'scope=openid' | jq -r .access_token)
```

If your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

As John, consume the API inside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

As John, consume the API outside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: The requested resource is not available in Italy
```

As John, consume a path of the API that will cause Envoy to skip external authorization:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api.127.0.0.1.nip.io:8000/global -i
# HTTP/1.1 200 OK
```

### Obtain an access token and consume the API as Jane (admin)

Obtain an access token with the Keycloak server for Jane, an admin user:

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' -d 'scope=openid' | jq -r .access_token)
```

As Jane, consume the API inside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

As Jane, consume the API outside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

As Jane, consume a path of the API that will cause Envoy to skip external authorization:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api.127.0.0.1.nip.io:8000/global -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete authconfig/talker-api-protection
kubectl delete ingress/ingress-wildcard-host
kubectl delete service/envoy
kubectl delete deployment/envoy
kubectl delete configmap/envoy
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
kubectl delete namespace keycloak
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
