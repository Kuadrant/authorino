# User guide: Mixing Envoy built-in filter for auth and Authorino

Have JWT validation handled by Envoy beforehand and the JWT payload injected into the request to Authorino, to be used in custom authorization policies defined in a AuthConfig.

In this user guide, we will set up Envoy and Authorino to protect a service called the _Talker API_ service, with JWT authentication handled in Envoy and a more complex authorization policy enforced in Authorino.

The policy defines a geo-fence by which only requests originated in Great Britain (country code: GB) will be accepted, unless the user is bound to a role called 'admin' in the auth server, in which case no geofence is enforced.

All requests to the Talker API will be authenticated in Envoy. However, requests to `/global` will **not** trigger the external authorization.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#plain-identityplain">Plain</a></li>
      <li>External auth metadata → <a href="./../features.md#http-getget-by-post-metadatahttp">HTTP GET/GET-by-POST</a></li>
      <li>Authorization → <a href="./../features.md#json-pattern-matching-authorization-rules-authorizationjson">JSON pattern-matching authorization rules</a></li>
      <li>Dynamic response → <a href="./../features.md#extra-custom-denial-status-denywith">Custom denial status</a></li>
    </ul>
  </summary>

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- Auth server / Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq), to extract parts of JSON responses

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-trial
```

Deploy a Keycloak server preloaded with all the realm settings required for this guide:

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

## 1. Install the Authorino Operator

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
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

The command below creates the Envoy configuration and deploys the Envoy proxy wire up the Talker API and external authorization with Authorino.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#1-setup-envoy) page. For a simpler and straighforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl -n authorino apply -f -<<EOF
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
                      issuer: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
                      remote_jwks:
                        http_uri:
                          uri: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/certs
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
  - host: talker-api-authorino.127.0.0.1.nip.io
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

For convinience, an `Ingress` resource is defined with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
```

## 6. Deploy the IP Location service

```sh
kubectl -n authorino apply -f https://raw.githubusercontent.com/Kuadrant/authorino-examples/main/ip-location/ip-location-deploy.yaml
```

## 7. Create the `AuthConfig`

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
  identity:
  - name: jwt
    plain:
      authJSON: context.metadata_context.filter_metadata.envoy\.filters\.http\.jwt_authn|verified_jwt
  metadata:
  - name: geoinfo
    http:
      endpoint: http://ip-location.authorino.svc.cluster.local:3000/{context.request.http.headers.x-forwarded-for.@extract:{"sep":","}}
      method: GET
      headers:
      - name: Accept
        value: application/json
    cache:
      key:
        valueFrom: { authJSON: "context.request.http.headers.x-forwarded-for.@extract:{\"sep\":\",\"}" }
  authorization:
  - name: geofence
    when:
    - selector: auth.identity.realm_access.roles
      operator: excl
      value: admin
    json:
      rules:
      - selector: auth.metadata.geoinfo.country_iso_code
        operator: eq
        value: "GB"
  denyWith:
    unauthorized:
      message:
        valueFrom: { authJSON: "The requested resource is not available in {auth.metadata.geoinfo.country_name}" }
EOF
```

## 8. Obtain a token and consume the API

### Obtain an access token and consume the API as John (member)

Obtain an access token with the Keycloak server for John:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user John, a non-admin (member) user:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' | jq -r .access_token)
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

As John, consume the API inside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

As John, consume the API outside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: The requested resource is not available in Italy
```

As John, consume a path of the API that will cause Envoy to skip external authorization:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/global -i
# HTTP/1.1 200 OK
```

### Obtain an access token and consume the API as Jane (admin)

Obtain an access token with the Keycloak server for Jane, an admin user:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r .access_token)
```

As Jane, consume the API inside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 79.123.45.67' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

As Jane, consume the API outside the area where the policy applies:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

As Jane, consume a path of the API that will cause Envoy to skip external authorization:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'X-Forwarded-For: 109.69.200.56' \
     http://talker-api-authorino.127.0.0.1.nip.io:8000/global -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-trial
```

Otherwise, delete the namespaces created in step 1 and 2:

```sh
kubectl -n authorino namespace authorino
kubectl -n authorino namespace authorino-operator
```

To uninstall the Authorino and Authorino Operator manifests, run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
